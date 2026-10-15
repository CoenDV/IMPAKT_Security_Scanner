namespace Compliance_Scanner;

/// <summary>
/// Human-readable diagnostic logging on stderr; stdout is reserved for JSON scan results.
/// </summary>
public sealed class ConsoleReporter : BaseReporter
{
    public ConsoleReporter(OutputLevel level = OutputLevel.Standard) : base(level) { }

    protected override void Write(string text, ConsoleColor? color = null)
        => Console.Error.Write(text);

    protected override void WriteLine(string text = "", ConsoleColor? color = null)
        => Console.Error.WriteLine(text);
}
