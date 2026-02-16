using System.Text.RegularExpressions;

namespace SecurityAgent.Bot;

/// <summary>
/// Enhances agent response text with emoji status indicators for Teams.
/// Teams renders markdown natively, so we enrich the text rather than
/// converting to Adaptive Cards (which have rendering inconsistencies).
/// </summary>
public static class MessageFormatter
{
    /// <summary>
    /// Enhance an agent response with emoji status indicators.
    /// </summary>
    public static string EnhanceMessage(string message)
    {
        // Process line by line
        var lines = message.Split('\n');
        var enhanced = new List<string>();

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            var trimmed = line.Trim();

            // Table data rows — add indicators to status cells
            if (IsTableRow(trimmed) && !(i + 1 < lines.Length && IsTableSeparator(lines[i + 1].Trim())))
            {
                enhanced.Add(EnhanceTableRow(line));
                continue;
            }

            // Bullet list items
            if (trimmed.StartsWith("- ") || trimmed.StartsWith("* "))
            {
                enhanced.Add(EnhanceBulletItem(line));
                continue;
            }

            // Key-value lines (e.g., "- Compliance State: Noncompliant")
            if (trimmed.Contains(':'))
            {
                enhanced.Add(EnhanceKeyValueLine(line));
                continue;
            }

            // Pass through everything else
            enhanced.Add(line);
        }

        return string.Join('\n', enhanced);
    }

    /// <summary>
    /// Enhance a markdown table row by adding emoji indicators to status cells.
    /// </summary>
    private static string EnhanceTableRow(string line)
    {
        var cells = line.Split('|');
        for (int i = 0; i < cells.Length; i++)
        {
            var cell = cells[i].Trim();
            var indicator = GetStatusIndicator(cell);
            if (indicator != null)
            {
                cells[i] = cells[i].Replace(cell, $"{indicator} {cell}");
            }
        }
        return string.Join('|', cells);
    }

    /// <summary>
    /// Enhance a bullet list item with status indicators.
    /// </summary>
    private static string EnhanceBulletItem(string line)
    {
        return EnhanceStatusWords(line);
    }

    /// <summary>
    /// Enhance key-value lines like "Compliance State: Noncompliant"
    /// </summary>
    private static string EnhanceKeyValueLine(string line)
    {
        return EnhanceStatusWords(line);
    }

    /// <summary>
    /// Add emoji indicators to known status words within text.
    /// Handles both standalone words and bold markdown words.
    /// </summary>
    private static string EnhanceStatusWords(string text)
    {
        // Replace standalone status words (case-insensitive, word boundary)
        // Only match when the status word is at the end of a phrase, after a colon,
        // or is bold — to avoid false positives

        // Bold status words: **Noncompliant** → 🔴 **Noncompliant**
        text = Regex.Replace(text, @"\*\*(Noncompliant|Non-compliant)\*\*", "🔴 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Compliant)\*\*", "🟢 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Critical)\*\*", "🔴 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(High)\*\*", "🟠 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Medium)\*\*", "🟡 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Low)\*\*", "🟢 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Informational)\*\*", "🔵 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Enabled)\*\*", "🟢 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Disabled)\*\*", "🔴 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Active)\*\*", "🟡 **$1**", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"\*\*(Resolved)\*\*", "🟢 **$1**", RegexOptions.IgnoreCase);

        // Status words after colons: "Compliance State: Noncompliant"
        text = Regex.Replace(text, @":\s*(Noncompliant|Non-compliant)\b", ": 🔴 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Compliant)\b", ": 🟢 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Critical)\b", ": 🔴 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(High)\b", ": 🟠 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Medium)\b", ": 🟡 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Low)\b", ": 🟢 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Informational)\b", ": 🔵 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Enabled)\b", ": 🟢 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Disabled)\b", ": 🔴 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Active)\b", ": 🟡 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @":\s*(Resolved)\b", ": 🟢 $1", RegexOptions.IgnoreCase);

        // Encryption status
        text = Regex.Replace(text, @"Encryption:\s*(Enabled)", "Encryption: 🟢 $1", RegexOptions.IgnoreCase);
        text = Regex.Replace(text, @"Encryption:\s*(Disabled)", "Encryption: 🔴 $1", RegexOptions.IgnoreCase);

        return text;
    }

    /// <summary>
    /// Get an emoji indicator for a standalone cell value in a table.
    /// Returns null if no indicator applies.
    /// </summary>
    private static string? GetStatusIndicator(string text)
    {
        var lower = text.ToLowerInvariant().Trim();

        return lower switch
        {
            "critical" => "🔴",
            "high" => "🟠",
            "medium" => "🟡",
            "low" => "🟢",
            "informational" or "info" => "🔵",
            "noncompliant" or "non-compliant" => "🔴",
            "compliant" => "🟢",
            "enabled" => "🟢",
            "disabled" => "🔴",
            "active" => "🟡",
            "resolved" => "🟢",
            "redirected" => "🔵",
            _ => null
        };
    }

    // ── Helpers ──

    private static bool IsTableRow(string line)
    {
        return line.StartsWith('|') && line.EndsWith('|') && line.Count(c => c == '|') >= 3;
    }

    private static bool IsTableSeparator(string line)
    {
        return line.StartsWith('|') && line.Contains("---");
    }
}
