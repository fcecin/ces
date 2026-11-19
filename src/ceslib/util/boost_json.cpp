// boost_json.cpp - the implementation of Boost.JSON. ceslib uses Boost.JSON
// header-only and links no Boost.JSON library. Only this unit includes
// boost/json/src.hpp. A program that compiles its own copy can link ceslib,
// because the linker then does not take this unit from the archive.

#include <boost/json/src.hpp>
