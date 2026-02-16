using Microsoft.Bot.Schema;
using Newtonsoft.Json.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SecurityAgent.Bot;

/// <summary>
/// Builds Adaptive Cards from agent responses that contain markdown tables.
/// Uses schema 1.5 with Table element. Content is serialized as JObject
/// because the Bot Framework SDK uses Newtonsoft.Json internally.
/// </summary>
public static class AdaptiveCardBuilder
{
    /// <summary>
    /// Try to build an Adaptive Card from the response.
    /// Returns null if there's no markdown table to render as a card.
    /// </summary>
    public static Attachment? TryBuildCard(string message)
    {
        if (!HasMarkdownTable(message))
            return null;

        var body = BuildBody(message);
        if (body.Count == 0)
            return null;

        // Build the card as a dictionary, then serialize to JSON string,
        // then parse as Newtonsoft JObject — this is what Bot Framework expects.
        var card = new Dictionary<string, object>
        {
            ["type"] = "AdaptiveCard",
            ["$schema"] = "http://adaptivecards.io/schemas/adaptive-card.json",
            ["version"] = "1.5",
            ["msteams"] = new Dictionary<string, object> { ["width"] = "Full" },
            ["body"] = body
        };

        var json = System.Text.Json.JsonSerializer.Serialize(card);

        return new Attachment
        {
            ContentType = "application/vnd.microsoft.card.adaptive",
            Content = JObject.Parse(json)
        };
    }

    private static bool HasMarkdownTable(string message)
    {
        var lines = message.Split('\n');
        for (int i = 0; i < lines.Length - 1; i++)
        {
            if (IsTableRow(lines[i].Trim()) && IsTableSeparator(lines[i + 1].Trim()))
                return true;
        }
        return false;
    }

    private static List<object> BuildBody(string message)
    {
        var body = new List<object>();
        var lines = message.Split('\n');
        var i = 0;

        while (i < lines.Length)
        {
            var trimmed = lines[i].Trim();

            if (string.IsNullOrWhiteSpace(trimmed))
            {
                i++;
                continue;
            }

            // Markdown table
            if (IsTableRow(trimmed) && i + 1 < lines.Length && IsTableSeparator(lines[i + 1].Trim()))
            {
                var (tableElement, nextIndex) = BuildTable(lines, i);
                body.Add(tableElement);
                i = nextIndex;
                continue;
            }

            // Code block
            if (trimmed.StartsWith("```"))
            {
                var (codeBlock, nextIndex) = BuildCodeBlock(lines, i);
                body.Add(codeBlock);
                i = nextIndex;
                continue;
            }

            // Header
            if (trimmed.StartsWith("## ") || trimmed.StartsWith("### "))
            {
                body.Add(new Dictionary<string, object>
                {
                    ["type"] = "TextBlock",
                    ["text"] = trimmed.TrimStart('#').Trim(),
                    ["weight"] = "bolder",
                    ["size"] = "medium",
                    ["color"] = "accent",
                    ["spacing"] = "medium",
                    ["wrap"] = true
                });
                i++;
                continue;
            }

            // Bullet list
            if (trimmed.StartsWith("- ") || trimmed.StartsWith("* "))
            {
                var (list, nextIndex) = BuildList(lines, i, bullet: true);
                body.Add(list);
                i = nextIndex;
                continue;
            }

            // Numbered list
            if (Regex.IsMatch(trimmed, @"^\d+\.\s"))
            {
                var (list, nextIndex) = BuildList(lines, i, bullet: false);
                body.Add(list);
                i = nextIndex;
                continue;
            }

            // Regular text — apply inline emoji enhancement
            body.Add(new Dictionary<string, object>
            {
                ["type"] = "TextBlock",
                ["text"] = MessageFormatter.EnhanceMessage(trimmed),
                ["wrap"] = true,
                ["size"] = "small"
            });
            i++;
        }

        return body;
    }

    // ── TABLE ──

    private static (object table, int nextIndex) BuildTable(string[] lines, int startIndex)
    {
        var headerCells = ParseTableRow(lines[startIndex]);
        var dataStartIndex = startIndex + 2;

        // Build column definitions
        var columns = headerCells.Select(_ => (object)new Dictionary<string, object>
        {
            ["width"] = 1
        }).ToList();

        var rows = new List<object>();

        // Header row
        rows.Add(new Dictionary<string, object>
        {
            ["type"] = "TableRow",
            ["style"] = "accent",
            ["cells"] = headerCells.Select(h => (object)new Dictionary<string, object>
            {
                ["type"] = "TableCell",
                ["items"] = new List<object>
                {
                    new Dictionary<string, object>
                    {
                        ["type"] = "TextBlock",
                        ["text"] = h.Trim(),
                        ["weight"] = "bolder",
                        ["size"] = "small",
                        ["wrap"] = true
                    }
                }
            }).ToList()
        });

        // Data rows
        var i = dataStartIndex;
        while (i < lines.Length && IsTableRow(lines[i].Trim()))
        {
            var cells = ParseTableRow(lines[i]);
            rows.Add(new Dictionary<string, object>
            {
                ["type"] = "TableRow",
                ["cells"] = cells.Select((c, idx) => (object)new Dictionary<string, object>
                {
                    ["type"] = "TableCell",
                    ["items"] = new List<object>
                    {
                        new Dictionary<string, object>
                        {
                            ["type"] = "TextBlock",
                            ["text"] = AddCellIndicator(c.Trim()),
                            ["size"] = "small",
                            ["wrap"] = true
                        }
                    }
                }).ToList()
            });
            i++;
        }

        var table = new Dictionary<string, object>
        {
            ["type"] = "Table",
            ["gridStyle"] = "accent",
            ["showGridLines"] = true,
            ["columns"] = columns,
            ["rows"] = rows
        };

        return (table, i);
    }

    // ── CODE BLOCK ──

    private static (object block, int nextIndex) BuildCodeBlock(string[] lines, int startIndex)
    {
        var codeLines = new List<string>();
        var i = startIndex + 1;

        while (i < lines.Length && !lines[i].Trim().StartsWith("```"))
        {
            codeLines.Add(lines[i]);
            i++;
        }
        if (i < lines.Length) i++;

        return (new Dictionary<string, object>
        {
            ["type"] = "Container",
            ["style"] = "emphasis",
            ["items"] = new List<object>
            {
                new Dictionary<string, object>
                {
                    ["type"] = "TextBlock",
                    ["text"] = string.Join("\n", codeLines).Trim(),
                    ["fontType"] = "monospace",
                    ["size"] = "small",
                    ["wrap"] = true
                }
            }
        }, i);
    }

    // ── LIST ──

    private static (object list, int nextIndex) BuildList(string[] lines, int startIndex, bool bullet)
    {
        var items = new List<object>();
        var i = startIndex;

        while (i < lines.Length)
        {
            var trimmed = lines[i].Trim();
            string text;
            string prefix;

            if (bullet)
            {
                if (!trimmed.StartsWith("- ") && !trimmed.StartsWith("* "))
                    break;
                text = trimmed[2..].Trim();
                prefix = "•";
            }
            else
            {
                if (!Regex.IsMatch(trimmed, @"^\d+\.\s"))
                    break;
                var match = Regex.Match(trimmed, @"^(\d+)\.\s(.*)");
                prefix = match.Groups[1].Value + ".";
                text = match.Groups[2].Value.Trim();
            }

            items.Add(new Dictionary<string, object>
            {
                ["type"] = "TextBlock",
                ["text"] = $"{prefix} {MessageFormatter.EnhanceMessage(text)}",
                ["size"] = "small",
                ["wrap"] = true,
                ["spacing"] = "small"
            });
            i++;
        }

        return (new Dictionary<string, object>
        {
            ["type"] = "Container",
            ["items"] = items
        }, i);
    }

    // ── HELPERS ──

    private static bool IsTableRow(string line)
    {
        return line.StartsWith('|') && line.EndsWith('|') && line.Count(c => c == '|') >= 3;
    }

    private static bool IsTableSeparator(string line)
    {
        return line.StartsWith('|') && line.Contains("---");
    }

    private static List<string> ParseTableRow(string line)
    {
        return line.Trim('|').Split('|').Select(c => c.Trim()).ToList();
    }

    private static string AddCellIndicator(string text)
    {
        var lower = text.ToLowerInvariant().Trim();
        var emoji = lower switch
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
        return emoji != null ? $"{emoji} {text}" : text;
    }
}
