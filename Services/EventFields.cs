using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace FirewallManager
{
    /// <summary>
    /// The named fields of an event (EventData/Data Name="…"), matched ignoring case: Windows
    /// doesn't keep a field's spelling across events (5156 writes ProcessId, 5157 ProcessID).
    /// Should two names differ only in case, the first is kept.
    /// </summary>
    internal static class EventFields
    {
        private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

        public static Dictionary<string, string> Of(EventRecord ev)
        {
            var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var d in XDocument.Parse(ev.ToXml()).Descendants(Ns + "Data"))
                if (d.Attribute("Name") is { } name) data.TryAdd(name.Value, d.Value);
            return data;
        }
    }
}
