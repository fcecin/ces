// SMTP submission client tests. An in-process mock SMTP server accepts one
// connection, speaks enough SMTP to complete a submission, and records the AUTH
// exchange + envelope + DATA payload. smtpSend is exercised against it, proving
// the client's handshake, AUTH LOGIN (mocked credentials), and message framing.
// TLS is not implemented and is not exercised here (see util/smtp.h).

#ifdef CES_MAIL

#define BOOST_TEST_DYN_LINK
#include "test_common.h"

#include <ces/util/smtp.h>

#include <boost/asio.hpp>
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <string>
#include <thread>

using namespace ces;
using boost::asio::ip::tcp;

namespace {

struct MockSmtp {
  boost::asio::io_context io;
  tcp::acceptor acc;
  std::thread th;
  uint16_t port = 0;
  std::string authUserB64, authPassB64, mailFrom, rcptTo, data;
  bool completed = false;

  MockSmtp() : acc(io, tcp::endpoint(tcp::v4(), 0)) {
    port = acc.local_endpoint().port();
    th = std::thread([this] { run(); });
  }
  ~MockSmtp() {
    io.stop();
    if (th.joinable()) th.join();
  }

  static std::string line(tcp::socket& s, boost::asio::streambuf& b) {
    boost::asio::read_until(s, b, "\r\n");
    std::istream is(&b);
    std::string l;
    std::getline(is, l);
    if (!l.empty() && l.back() == '\r') l.pop_back();
    return l;
  }
  static void say(tcp::socket& s, const std::string& r) {
    boost::asio::write(s, boost::asio::buffer(r + "\r\n"));
  }

  void run() {
    try {
      tcp::socket s(io);
      boost::system::error_code ec;
      acc.accept(s, ec);
      if (ec) return;
      boost::asio::streambuf b;
      say(s, "220 mock ESMTP");
      for (;;) {
        std::string l = line(s, b);
        if (l.rfind("EHLO", 0) == 0) {
          say(s, "250-mock");
          say(s, "250 AUTH LOGIN");
        } else if (l == "AUTH LOGIN") {
          say(s, "334 VXNlcm5hbWU6");
          authUserB64 = line(s, b);
          say(s, "334 UGFzc3dvcmQ6");
          authPassB64 = line(s, b);
          say(s, "235 ok");
        } else if (l.rfind("MAIL FROM:", 0) == 0) {
          mailFrom = l;
          say(s, "250 ok");
        } else if (l.rfind("RCPT TO:", 0) == 0) {
          rcptTo = l;
          say(s, "250 ok");
        } else if (l == "DATA") {
          say(s, "354 go");
          for (;;) {
            std::string d = line(s, b);
            if (d == ".") break;
            data += d + "\n";
          }
          say(s, "250 queued");
          completed = true;
        } else if (l == "QUIT") {
          say(s, "221 bye");
          break;
        } else {
          say(s, "250 ok");
        }
      }
    } catch (...) {
    }
  }
};

}  // namespace

BOOST_AUTO_TEST_SUITE(SmtpTests)

BOOST_AUTO_TEST_CASE(Submit_WithAuth_DeliversEnvelopeAndBody) {
  MockSmtp mock;
  SmtpConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = mock.port;
  cfg.from = "relay@ces";
  cfg.user = "u";
  cfg.pass = "p";
  std::string err;
  bool ok = smtpSend(cfg, "claudia@example.com", "Subject X", "Body Y",
                     nullptr, &err);
  BOOST_CHECK_MESSAGE(ok, "smtpSend failed: " << err);

  for (int i = 0; i < 100 && !mock.completed; ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

  BOOST_CHECK(mock.completed);
  BOOST_CHECK_EQUAL(mock.mailFrom, "MAIL FROM:<relay@ces>");
  BOOST_CHECK_EQUAL(mock.rcptTo, "RCPT TO:<claudia@example.com>");
  BOOST_CHECK(mock.data.find("Subject: Subject X") != std::string::npos);
  BOOST_CHECK(mock.data.find("To: claudia@example.com") != std::string::npos);
  BOOST_CHECK(mock.data.find("Body Y") != std::string::npos);
  BOOST_CHECK_EQUAL(mock.authUserB64, "dQ==");   // base64("u")
  BOOST_CHECK_EQUAL(mock.authPassB64, "cA==");   // base64("p")
}

BOOST_AUTO_TEST_CASE(Submit_WithAttachment_SendsMimeMultipart) {
  MockSmtp mock;
  SmtpConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = mock.port;
  cfg.from = "relay@ces";
  MailAttachment att;
  att.filename = "note.txt";
  att.contentType = "text/plain";
  att.data = "hi";   // base64 -> "aGk="
  std::string err;
  bool ok = smtpSend(cfg, "u@example.com", "Subj", "Text body", &att, &err);
  BOOST_CHECK_MESSAGE(ok, "smtpSend failed: " << err);

  for (int i = 0; i < 100 && !mock.completed; ++i)
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

  BOOST_CHECK(mock.completed);
  BOOST_CHECK(mock.data.find("multipart/mixed") != std::string::npos);
  BOOST_CHECK(mock.data.find("filename=\"note.txt\"") != std::string::npos);
  BOOST_CHECK(mock.data.find("Content-Transfer-Encoding: base64") !=
              std::string::npos);
  BOOST_CHECK(mock.data.find("Text body") != std::string::npos);
  BOOST_CHECK(mock.data.find("aGk=") != std::string::npos);   // base64("hi")
}

// Regression for review item 7 (SMTP injection). 'to' and 'subject' are
// program-controlled via ces.mail_send (length-checked only), so a CRLF must not
// smuggle a second SMTP command (RCPT TO / BCC) or a forged header. smtpSend
// rejects a control char in the envelope/header fields BEFORE any network I/O.
// No mock: the point is that nothing is sent. The "control character" error
// discriminates the fix from an ordinary connect failure -- without the fix,
// smtpSend would try to connect (and err would be a connect/resolve message)
// while smuggling the injected RCPT into the dialog.
BOOST_AUTO_TEST_CASE(RejectsCrlfInjectionInEnvelope) {
  SmtpConfig cfg;
  cfg.host = "127.0.0.1";
  cfg.port = 1;   // nothing listening; the fix must reject before connecting
  cfg.from = "relay@ces";

  std::string err;
  bool ok = smtpSend(cfg, "victim@example.com>\r\nRCPT TO:<attacker@evil.com",
                     "Subj", "Body", nullptr, &err);
  BOOST_CHECK(!ok);
  BOOST_CHECK_MESSAGE(err.find("control character") != std::string::npos,
                      "expected a CRLF rejection, got: " << err);

  // A CRLF in the subject (which lands in a header) is refused the same way.
  std::string err2;
  bool ok2 = smtpSend(cfg, "ok@example.com", "Subj\r\nBcc: evil@evil.com",
                      "Body", nullptr, &err2);
  BOOST_CHECK(!ok2);
  BOOST_CHECK(err2.find("control character") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()

#endif  // CES_MAIL
