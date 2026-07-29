# Applied to the fetched MINX source (PATCH_COMMAND, CWD = minx source dir):
# Boost >= 1.87 removed deprecated asio APIs, and >= 1.90 dropped the
# boost_system component config. string(REPLACE) is idempotent -- an absent
# pattern changes nothing, so re-population is safe.
macro(subst f old new)
  file(READ ${f} _c)
  string(REPLACE "${old}" "${new}" _c "${_c}")
  file(WRITE ${f} "${_c}")
endmacro()

subst(CMakeLists.txt
  "find_package(Boost 1.83.0 REQUIRED COMPONENTS system log log_setup)"
  "find_package(Boost 1.83.0 REQUIRED COMPONENTS log log_setup)")

subst(include/minx/filter.h
  "addr = addr.to_v6().to_v4();"
  "addr = boost::asio::ip::make_address_v4(boost::asio::ip::v4_mapped, addr.to_v6());")

subst(src/minx.cpp
  "netIORetryTimer_->cancel(ec);"
  "(void)ec; netIORetryTimer_->cancel();")

subst(src/minxrunner.cpp "netIO_.reset();" "netIO_.restart();")
subst(src/minxrunner.cpp "taskIO_.reset();" "taskIO_.restart();")
