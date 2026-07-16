// Mail end-to-end tests over REAL TLS (--mail only).
//
// SendReceiveOverTLS stands up an in-process SMTP receiver that mints a
// self-signed cert at runtime (OpenSSL), advertises STARTTLS, completes a real
// TLS handshake, and captures the fully-decrypted submission. smtpSend is driven
// against it, exercising the production STARTTLS path end to end: capability
// detection, the TLS upgrade, AUTH LOGIN over the encrypted channel, the MIME
// multipart body and dot-stuffing. The receiver then asserts the envelope and
// content are correct -- send + receive + verify, over genuine TLS crypto.
//
// Sending against a live provider (Resend, Postfix, ...) is a manual, local-only
// step -- see local/mail_send.cpp, a standalone CLI that takes credentials on
// argv. It is deliberately NOT a suite test: CES tests never take runtime input
// from the environment or the network, and no credentials live in the tree.

#ifdef CES_MAIL

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/util/smtp.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/test/unit_test.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <chrono>
#include <string>
#include <thread>

using namespace ces;
using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

namespace {

// A short-lived self-signed RSA cert (CN=localhost) for the test TLS server.
// Owns the OpenSSL objects; frees them on destruction.
struct SelfSigned {
  EVP_PKEY* pkey = nullptr;
  X509*     x509 = nullptr;
  SelfSigned() {
    pkey = EVP_RSA_gen(2048);
    x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), 3600);   // 1 hour
    X509_set_pubkey(x509, pkey);
    X509_NAME* n = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"),
                               -1, -1, 0);
    X509_set_issuer_name(x509, n);                     // self-signed
    X509_sign(x509, pkey, EVP_sha256());
  }
  ~SelfSigned() {
    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);
  }
};

template <class S>
std::string readLine(S& s, boost::asio::streambuf& buf) {
  boost::asio::read_until(s, buf, "\r\n");
  std::istream is(&buf);
  std::string line;
  std::getline(is, line);
  if (!line.empty() && line.back() == '\r') line.pop_back();
  return line;
}

template <class S>
void writeLine(S& s, const std::string& l) {
  boost::asio::write(s, boost::asio::buffer(l + "\r\n"));
}

// What the in-process receiver captured.
struct Received {
  bool        tlsUsed = false;
  bool        completed = false;
  std::string mailFrom;
  std::string rcptTo;
  std::string authUserB64;
  std::string data;
};

}  // namespace

BOOST_AUTO_TEST_SUITE(MailE2ETests)

// Real STARTTLS: smtpSend upgrades to TLS and delivers; the receiver decrypts
// and verifies the envelope + MIME body.
BOOST_AUTO_TEST_CASE(SendReceiveOverTLS) {
  SelfSigned cert;
  ssl::context serverCtx(ssl::context::tls_server);
  SSL_CTX* raw = serverCtx.native_handle();
  BOOST_REQUIRE_EQUAL(SSL_CTX_use_certificate(raw, cert.x509), 1);
  BOOST_REQUIRE_EQUAL(SSL_CTX_use_PrivateKey(raw, cert.pkey), 1);

  boost::asio::io_context io;
  tcp::acceptor acc(io, tcp::endpoint(tcp::v4(), 0));   // ephemeral port
  const uint16_t port = acc.local_endpoint().port();

  Received rec;
  std::thread server([&] {
    try {
      ssl::stream<tcp::socket> s(io, serverCtx);
      acc.accept(s.next_layer());
      boost::asio::streambuf buf;

      // Plaintext SMTP prelude.
      writeLine(s.next_layer(), "220 ces-test ESMTP");
      readLine(s.next_layer(), buf);                    // EHLO
      writeLine(s.next_layer(), "250-ces-test");
      writeLine(s.next_layer(), "250 STARTTLS");        // advertise STARTTLS
      std::string line = readLine(s.next_layer(), buf); // STARTTLS
      if (line.substr(0, 8) != "STARTTLS") return;
      writeLine(s.next_layer(), "220 go ahead");

      // Real TLS handshake, then the encrypted submission.
      s.handshake(ssl::stream_base::server);
      rec.tlsUsed = true;

      readLine(s, buf);                                 // EHLO (over TLS)
      writeLine(s, "250 ces-test");
      for (;;) {
        line = readLine(s, buf);
        if (line.rfind("AUTH LOGIN", 0) == 0) {
          writeLine(s, "334 VXNlcm5hbWU6");             // "Username:"
          rec.authUserB64 = readLine(s, buf);
          writeLine(s, "334 UGFzc3dvcmQ6");             // "Password:"
          readLine(s, buf);                             // password (ignored)
          writeLine(s, "235 2.7.0 accepted");
        } else if (line.rfind("MAIL FROM:", 0) == 0) {
          rec.mailFrom = line;
          writeLine(s, "250 2.1.0 ok");
        } else if (line.rfind("RCPT TO:", 0) == 0) {
          rec.rcptTo = line;
          writeLine(s, "250 2.1.5 ok");
        } else if (line.rfind("DATA", 0) == 0) {
          writeLine(s, "354 end with .");
          // Body up to the CRLF "." CRLF terminator.
          boost::asio::read_until(s, buf, "\r\n.\r\n");
          std::istream is(&buf);
          std::string all((std::istreambuf_iterator<char>(is)),
                          std::istreambuf_iterator<char>());
          rec.data = all;
          writeLine(s, "250 2.0.0 queued");
        } else if (line.rfind("QUIT", 0) == 0) {
          writeLine(s, "221 2.0.0 bye");
          rec.completed = true;
          break;
        } else {
          break;
        }
      }
    } catch (...) {
      // Leave rec.completed false; the assertions below fail with context.
    }
  });

  SmtpConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = port;
  cfg.from = "ces@example.com";
  cfg.user = "relay-user";
  cfg.pass = "relay-pass";

  MailAttachment att;
  att.filename = "note.txt";
  att.data = "hi";                                      // base64 -> "aGk="

  std::string err;
  bool ok = smtpSend(cfg, "dest@example.com", "TLS Subject",
                     "Encrypted body line", &att, &err);
  server.join();

  BOOST_CHECK_MESSAGE(ok, "smtpSend failed: " << err);
  BOOST_CHECK(rec.tlsUsed);                             // handshake happened
  BOOST_CHECK(rec.completed);
  BOOST_CHECK_EQUAL(rec.authUserB64, "cmVsYXktdXNlcg==");   // base64("relay-user")
  BOOST_CHECK(rec.mailFrom.find("ces@example.com") != std::string::npos);
  BOOST_CHECK(rec.rcptTo.find("dest@example.com") != std::string::npos);
  BOOST_CHECK(rec.data.find("Subject: TLS Subject") != std::string::npos);
  BOOST_CHECK(rec.data.find("Encrypted body line") != std::string::npos);
  BOOST_CHECK(rec.data.find("multipart/mixed") != std::string::npos);
  BOOST_CHECK(rec.data.find("aGk=") != std::string::npos);  // attachment base64
}

// A relay that accepts the connection then goes silent must not hang the client:
// the watchdog shuts the socket down and smtpSend fails within timeout_secs.
BOOST_AUTO_TEST_CASE(StallTimeout) {
  boost::asio::io_context io;
  tcp::acceptor acc(io, tcp::endpoint(tcp::v4(), 0));
  const uint16_t port = acc.local_endpoint().port();

  std::thread server([&] {
    try {
      tcp::socket s(io);
      acc.accept(s);
      boost::asio::write(s, boost::asio::buffer(std::string("220 stall\r\n")));
      boost::asio::streambuf b;                 // then never reply; hold open
      boost::system::error_code ec;
      boost::asio::read(s, b, ec);              // returns when the client gives up
    } catch (...) {
    }
  });

  SmtpConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = port;
  cfg.timeout_secs = 1;                         // short, for the test

  const auto t0 = std::chrono::steady_clock::now();
  std::string err;
  bool ok = smtpSend(cfg, "a@b.c", "s", "b", nullptr, &err);
  const auto secs = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::steady_clock::now() - t0).count();
  server.join();

  BOOST_CHECK(!ok);                             // failed rather than hung
  BOOST_CHECK_LT(secs, 5);                      // bounded near timeout_secs
}

BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_MAIL
