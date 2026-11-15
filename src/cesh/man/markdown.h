// Markdown to HTML for the pages of the cesh manual.
//
// It covers the markdown that the pages use: ATX headings, paragraphs, "-"
// and "1." lists, fenced code, pipe tables, "> " quotes, "---" rules, and
// inline code, **bold**, *italic* and [links](target). All text is escaped.
// It is not a full CommonMark parser.

#pragma once

#include <functional>
#include <string>
#include <string_view>

namespace ces::man {

// Maps a link target of the page to the href to write. Return the target
// unchanged for an external link.
using LinkMap = std::function<std::string(std::string_view target)>;

std::string escapeHtml(std::string_view s);

std::string markdownToHtml(std::string_view md, const LinkMap& link);

// The same markdown for a terminal, with ANSI styles: headings and **bold**
// in bold, *italic*, `code` in cyan, fenced code indented and dim, links as
// "text (target)", and pipe tables aligned in columns.
std::string markdownToTerminal(std::string_view md);

}  // namespace ces::man
