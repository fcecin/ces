// smtp.cpp - see smtp.h. Synchronous SMTP submission over Boost.Asio, with
// opportunistic STARTTLS (OpenSSL) when the relay advertises it.

#ifdef CES_MAIL

#include <ces/util/smtp.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/ssl.h>

#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

namespace ces {
namespace {

using boost::asio::ip::tcp;
namespace ssl = boost::asio::ssl;

std::string b64(const std::string& in) {
  static const char* T =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  int val = 0, bits = -6;
  for (unsigned char c : in) {
    val = (val << 8) + c;
    bits += 8;
    while (bits >= 0) { out.push_back(T[(val >> bits) & 0x3F]); bits -= 6; }
  }
  if (bits > -6) out.push_back(T[((val << 8) >> (bits + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}

// base64 with CRLF wrapping at 76 chars (MIME attachment bodies).
std::string b64wrapped(const std::string& in) {
  std::string raw = b64(in);
  std::string out;
  out.reserve(raw.size() + raw.size() / 76 * 2 + 2);
  for (size_t i = 0; i < raw.size(); i += 76) {
    out += raw.substr(i, 76);
    out += "\r\n";
  }
  return out;
}

// SMTP dot-stuffing: any line beginning with '.' gets a doubled leading dot so
// it is not mistaken for the end-of-DATA terminator.
std::string dotStuff(const std::string& msg) {
  std::string out;
  out.reserve(msg.size());
  bool atLineStart = true;
  for (char c : msg) {
    if (atLineStart && c == '.') out.push_back('.');
    out.push_back(c);
    atLineStart = (c == '\n');
  }
  return out;
}

// Read one full SMTP reply (handling multiline continuations) and return its
// 3-digit code, or -1 on error. If `collect` is non-null every reply line is
// appended to it (used to scan EHLO capabilities). Templated so it works on a
// plain tcp::socket and on an ssl::stream after STARTTLS.
template <class Stream>
int readReply(Stream& s, boost::asio::streambuf& buf, std::string* err,
              std::string* collect = nullptr) {
  for (;;) {
    boost::system::error_code ec;
    boost::asio::read_until(s, buf, "\r\n", ec);
    if (ec) { if (err) *err = "read: " + ec.message(); return -1; }
    std::istream is(&buf);
    std::string line;
    std::getline(is, line);
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (collect) { *collect += line; collect->push_back('\n'); }
    if (line.size() < 4) continue;
    int code = std::atoi(line.substr(0, 3).c_str());
    if (line[3] == ' ') return code;   // final line (space, not '-')
  }
}

// Send `line` + CRLF and require the reply's class to match `expectClass`
// (2 or 3). Returns false (with diagnostic) otherwise.
template <class Stream>
bool cmd(Stream& s, boost::asio::streambuf& buf, const std::string& line,
         int expectClass, std::string* err) {
  boost::system::error_code ec;
  boost::asio::write(s, boost::asio::buffer(line + "\r\n"), ec);
  if (ec) { if (err) *err = "write: " + ec.message(); return false; }
  int code = readReply(s, buf, err);
  if (code < 0) return false;
  if (code / 100 != expectClass) {
    if (err) *err = "unexpected reply " + std::to_string(code);
    return false;
  }
  return true;
}

// Assemble the RFC 5322 message (a MIME multipart/mixed when an attachment is
// present, otherwise a plain text body).
std::string buildMessage(const SmtpConfig& cfg, const std::string& to,
                         const std::string& subject, const std::string& body,
                         const MailAttachment* attachment) {
  const std::string headers =
    "From: " + cfg.from + "\r\n" +
    "To: " + to + "\r\n" +
    "Subject: " + subject + "\r\n";
  if (!attachment) return headers + "\r\n" + body + "\r\n";
  const std::string b = "ces_mime_boundary_a1b2c3d4";
  return
    headers +
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"" + b + "\"\r\n"
    "\r\n"
    "--" + b + "\r\n"
    "Content-Type: text/plain; charset=utf-8\r\n"
    "\r\n" +
    body + "\r\n"
    "--" + b + "\r\n"
    "Content-Type: " + attachment->contentType +
    "; name=\"" + attachment->filename + "\"\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "Content-Disposition: attachment; filename=\"" +
    attachment->filename + "\"\r\n"
    "\r\n" +
    b64wrapped(attachment->data) +
    "--" + b + "--\r\n";
}

// Run the submission over an established stream (plaintext socket or TLS
// stream). `needEhlo` re-issues EHLO first, required after a STARTTLS upgrade.
template <class Stream>
bool deliver(Stream& s, boost::asio::streambuf& buf, const SmtpConfig& cfg,
             const std::string& to, const std::string& subject,
             const std::string& body, const MailAttachment* attachment,
             std::string* err, bool needEhlo) {
  if (needEhlo && !cmd(s, buf, "EHLO ces", 2, err)) return false;
  if (!cfg.user.empty()) {
    if (!cmd(s, buf, "AUTH LOGIN", 3, err)) return false;
    if (!cmd(s, buf, b64(cfg.user), 3, err)) return false;
    if (!cmd(s, buf, b64(cfg.pass), 2, err)) return false;
  }
  if (!cmd(s, buf, "MAIL FROM:<" + cfg.from + ">", 2, err)) return false;
  if (!cmd(s, buf, "RCPT TO:<" + to + ">", 2, err)) return false;
  if (!cmd(s, buf, "DATA", 3, err)) return false;   // 354
  // DATA terminator: dot-stuff the body, then append the "." line (cmd adds the
  // trailing CRLF, yielding the CRLF "." CRLF end marker).
  const std::string message = buildMessage(cfg, to, subject, body, attachment);
  if (!cmd(s, buf, dotStuff(message) + ".", 2, err)) return false;  // 250
  cmd(s, buf, "QUIT", 2, err);   // best-effort
  return true;
}

}  // namespace

bool smtpSend(const SmtpConfig& cfg, const std::string& to,
              const std::string& subject, const std::string& body,
              const MailAttachment* attachment, std::string* err) {
  // Envelope/header fields must not contain CR or LF: an embedded newline would
  // inject an extra SMTP command (a second RCPT TO / BCC) or a forged header.
  // `to` and `subject` are program-controlled (ces.mail_send validates only
  // length), so reject a control char here rather than pass it into the dialog.
  // `from` is operator config but checked for symmetry. Body is exempt: it is
  // dot-stuffed and framed by the "." terminator, not by bare CRLF.
  auto fieldSafe = [](const std::string& s) {
    return s.find('\r') == std::string::npos && s.find('\n') == std::string::npos;
  };
  if (!fieldSafe(to) || !fieldSafe(subject) || !fieldSafe(cfg.from)) {
    if (err) *err = "mail field contains a control character (CR/LF)";
    return false;
  }
  try {
    boost::asio::io_context io;
    ssl::context sslctx(ssl::context::tls_client);
    ssl::stream<tcp::socket> stream(io, sslctx);
    tcp::socket& sock = stream.next_layer();

    boost::system::error_code ec;
    tcp::resolver res(io);
    auto eps = res.resolve(cfg.host, std::to_string(cfg.port), ec);
    if (ec) { if (err) *err = "resolve: " + ec.message(); return false; }
    boost::asio::connect(sock, eps, ec);
    if (ec) { if (err) *err = "connect: " + ec.message(); return false; }

    // Watchdog: bound the whole synchronous exchange so a relay that accepts
    // then goes silent cannot hang the caller. On expiry, shut the socket down
    // (this unblocks the pending read) and close it; the in-flight op then fails
    // and smtpSend returns false. The Stop guard ends the watchdog on every
    // return path.
    std::mutex wm;
    std::condition_variable wcv;
    bool finished = false;
    std::thread watchdog([&] {
      try {
        std::unique_lock<std::mutex> lk(wm);
        if (!wcv.wait_for(lk, std::chrono::seconds(cfg.timeout_secs),
                          [&] { return finished; })) {
          boost::system::error_code ig;
          sock.shutdown(boost::asio::socket_base::shutdown_both, ig);
          sock.close(ig);
        }
      } catch (...) {
      }
    });
    struct Stop {
      std::mutex& m; std::condition_variable& cv; bool& f; std::thread& t;
      ~Stop() {
        { std::lock_guard<std::mutex> lk(m); f = true; }
        cv.notify_one();
        t.join();
      }
    } stop{wm, wcv, finished, watchdog};

    boost::asio::streambuf buf;
    if (readReply(sock, buf, err) / 100 != 2) return false;   // 220 greeting

    // EHLO in plaintext; collect the capability list to detect STARTTLS.
    boost::asio::write(sock, boost::asio::buffer(std::string("EHLO ces\r\n")), ec);
    if (ec) { if (err) *err = "write: " + ec.message(); return false; }
    std::string caps;
    int ehlo = readReply(sock, buf, err, &caps);
    if (ehlo < 0) return false;
    if (ehlo / 100 != 2) {
      if (err) *err = "EHLO rejected " + std::to_string(ehlo);
      return false;
    }

    if (caps.find("STARTTLS") != std::string::npos) {
      if (!cmd(sock, buf, "STARTTLS", 2, err)) return false;   // 220
      // Opportunistic TLS: encrypt, do not verify the peer cert.
      stream.set_verify_mode(ssl::verify_none);
      SSL_set_tlsext_host_name(stream.native_handle(), cfg.host.c_str());  // SNI
      stream.handshake(ssl::stream_base::client, ec);
      if (ec) { if (err) *err = "tls handshake: " + ec.message(); return false; }
      // RFC 3207: re-issue EHLO over the encrypted channel, then send.
      return deliver(stream, buf, cfg, to, subject, body, attachment, err, true);
    }
    // No STARTTLS advertised: proceed in plaintext (trusted hop or test mock).
    return deliver(sock, buf, cfg, to, subject, body, attachment, err, false);
  } catch (const std::exception& e) {
    if (err) *err = std::string("smtp exception: ") + e.what();
    return false;
  }
}

}  // namespace ces

#endif  // CES_MAIL
