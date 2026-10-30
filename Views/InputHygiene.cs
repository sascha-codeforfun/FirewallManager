using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using HueThemeKit;

namespace FirewallManager
{
    /// <summary>
    /// Character hygiene on one text box, for typing, paste and drop alike: a character the
    /// field can't hold is taken out where it was, and a note under the field names it and
    /// offers plain alternatives, which put the choice back in that place. Nothing is changed
    /// without being shown. Only what was just put in is looked at: text the app sets itself (a
    /// loaded rule, a preset) stays as it is. <see cref="NoteExisting"/> names what in such text
    /// doesn't fit, and offers the alternatives in its place, without changing it.
    /// </summary>
    internal sealed class InputHygiene
    {
        private sealed class Entry
        {
            public int Index;                 // where it was, in the text as it is now
            public Rune Character;
            public int Replaces;              // 0: taken out; else still in the text, this many units long
        }

        private readonly TextBox _box;
        private readonly Func<int, bool> _fits;
        private readonly bool _isName;
        private readonly Panel _note;
        private readonly List<Entry> _entries = new();
        private bool _editing;                // our own change: its TextChanged is not input
        private bool _pasting;                // a paste or drop arrives, even into an unfocused box

        public static InputHygiene ForName(TextBox box, Panel note)  => new(box, TextHygiene.IsNameChar, isName: true, note);
        public static InputHygiene ForPlain(TextBox box, Panel note) => new(box, TextHygiene.IsPlainAscii, isName: false, note);

        private InputHygiene(TextBox box, Func<int, bool> fits, bool isName, Panel note)
        {
            _box = box; _fits = fits; _isName = isName; _note = note;
            _note.Visibility = Visibility.Collapsed;
            DataObject.AddPastingHandler(box, (_, _) =>
            {
                _pasting = true;
                // The paste lands before this runs; a cancelled one mustn't mark the next change.
                box.Dispatcher.InvokeAsync(() => _pasting = false, System.Windows.Threading.DispatcherPriority.Background);
            });
            box.TextChanged += OnTextChanged;
        }

        /// <summary>
        /// Notes each character of the text as it stands that the field can't hold (a loaded
        /// rule's name with _), leaving the text as it is: an alternative replaces it when chosen.
        /// </summary>
        public void NoteExisting()
        {
            _entries.RemoveAll(x => x.Replaces > 0);
            var text = _box.Text;
            var at = 0;
            foreach (var r in text.EnumerateRunes())
            {
                if (!_fits(r.Value)) _entries.Add(new Entry { Index = at, Character = r, Replaces = r.Utf16SequenceLength });
                at += r.Utf16SequenceLength;
            }
            var sorted = _entries.OrderBy(x => x.Index).ToList();
            _entries.Clear();
            _entries.AddRange(sorted);
            Render();
        }

        private void OnTextChanged(object sender, TextChangedEventArgs e)
        {
            if (_editing) return;
            var input = _pasting || _box.IsKeyboardFocusWithin;
            _pasting = false;

            // The app set the text: what the note spoke of is gone.
            if (!input)
            {
                if (_entries.Count > 0) { _entries.Clear(); Render(); }
                return;
            }

            var changes = e.Changes.ToList();
            if (changes.Count == 0) return;
            var text = _box.Text;
            int start, end;
            if (changes.Count == 1)
            {
                var c = changes[0];
                Follow(c);
                start = c.Offset;
                end   = c.Offset + c.AddedLength;
            }
            else
            {
                // Several changes at once: their offsets can't be followed one by one.
                _entries.Clear();
                start = changes.Min(c => c.Offset);
                end   = changes.Max(c => c.Offset + c.AddedLength);
            }
            if (text.Length == 0) _entries.Clear();

            start = Math.Clamp(start, 0, text.Length);
            end   = Math.Clamp(end, start, text.Length);
            // Never split a character made of two UTF-16 units.
            if (start > 0 && start < text.Length && char.IsLowSurrogate(text[start]) && char.IsHighSurrogate(text[start - 1])) start--;
            if (end > 0 && end < text.Length && char.IsHighSurrogate(text[end - 1]) && char.IsLowSurrogate(text[end])) end++;

            var (kept, removed) = TextHygiene.Clean(text[start..end], _fits);
            if (removed.Count == 0) { Render(); return; }

            var caret = _box.CaretIndex;
            var shrink = (end - start) - kept.Length;
            var newCaret = caret <= start ? caret
                         : caret >= end   ? caret - shrink
                         : start + TextHygiene.Clean(text[start..caret], _fits).Text.Length;

            foreach (var x in _entries) if (x.Index >= end) x.Index -= shrink;
            var all = _entries.Concat(removed.Select(r => new Entry { Index = start + r.Index, Character = r.Character }))
                              .OrderBy(x => x.Index).ToList();      // stable: earlier entries stay first
            _entries.Clear();
            _entries.AddRange(all);

            SetText(text[..start] + kept + text[end..], newCaret);
            Render();
        }

        // Moves the noted places along with an edit; one whose surroundings were deleted goes.
        private void Follow(TextChange c)
        {
            var removedEnd = c.Offset + c.RemovedLength;
            // A character still in the text goes from the note when it is deleted or replaced.
            _entries.RemoveAll(x => x.Replaces > 0
                ? c.RemovedLength > 0 && c.Offset < x.Index + x.Replaces && removedEnd > x.Index
                : x.Index > c.Offset && x.Index < removedEnd);
            foreach (var x in _entries)
            {
                var moves = x.Replaces > 0 ? x.Index >= c.Offset && x.Index >= removedEnd
                                           : x.Index > c.Offset && x.Index >= removedEnd;
                if (moves) x.Index += c.AddedLength - c.RemovedLength;
            }
        }

        private void SetText(string text, int caret)
        {
            _editing = true;
            try
            {
                _box.Text = text;
                _box.CaretIndex = Math.Clamp(caret, 0, text.Length);
            }
            finally { _editing = false; }
        }

        private void Choose(Entry entry, string alternative)
        {
            var text = _box.Text;
            var at = Math.Clamp(entry.Index, 0, text.Length);
            var replaces = Math.Min(entry.Replaces, text.Length - at);
            var pos = _entries.IndexOf(entry);
            // Characters noted after this one move along by what goes in (and what goes out).
            for (var i = 0; i < _entries.Count; i++)
                if (_entries[i].Index > at || (i > pos && _entries[i].Index == at))
                    _entries[i].Index += alternative.Length - replaces;
            _entries.Remove(entry);
            SetText(text.Remove(at, replaces).Insert(at, alternative), at + alternative.Length);
            _box.Focus();
            Render();
        }

        // What can stand in for the character in this field; never chosen for the user.
        private IReadOnlyList<string> Alternatives(Rune r)
        {
            // In a name, _ stands for a space in the registry name: a space is what it means.
            if (_isName && r.Value == '_') return new[] { " " };
            return TextHygiene.Alternatives(r).Where(a => a.EnumerateRunes().All(x => _fits(x.Value))).ToList();
        }

        private void Render()
        {
            _note.Children.Clear();
            // A noted character still in the text must still be there, or there's nothing to replace.
            var text = _box.Text;
            _entries.RemoveAll(x => x.Replaces > 0 &&
                (x.Index < 0 || x.Index + x.Replaces > text.Length ||
                 string.CompareOrdinal(text, x.Index, x.Character.ToString(), 0, x.Replaces) != 0));
            if (_entries.Count == 0) { _note.Visibility = Visibility.Collapsed; return; }

            var lines = new StackPanel();
            foreach (var entry in _entries)
            {
                var line = new TextBlock { FontSize = 11, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 2) }
                    .Ref(TextBlock.ForegroundProperty, "Brush.TextMuted");
                var where = entry.Replaces > 0 ? (_isName ? "In the name" : "In the text") : "Taken out";
                line.Inlines.Add(new Run($"{where}: {TextHygiene.Describe(entry.Character)}."));
                // | and _ are plain ASCII, so say why a name can't hold them.
                var reason = _isName && (entry.Character.Value == '|' || entry.Character.Value == '_')
                    ? TextHygiene.BadName(entry.Character.ToString()) : null;
                if (reason != null) line.Inlines.Add(new Run(" " + reason));
                var alternatives = Alternatives(entry.Character);
                if (alternatives.Count > 0 && reason == null) line.Inlines.Add(new Run(" Use instead:"));
                foreach (var alternative in alternatives)
                {
                    var chosen = alternative;
                    var shown = chosen == " " ? "space" : chosen;
                    var button = new Button
                    {
                        Content = shown, FontSize = 11, MinHeight = 22, MinWidth = 22,
                        Padding = new Thickness(8, 0, 8, 0), Margin = new Thickness(6, 0, 0, 0),
                        ToolTip = $"Put {(chosen == " " ? "a space" : chosen)} {(entry.Replaces > 0 ? "in its place" : "where it was")}",
                    }.Styled("Hue.Button");
                    var target = entry;
                    button.Click += (_, _) => Choose(target, chosen);
                    line.Inlines.Add(new InlineUIContainer(button) { BaselineAlignment = BaselineAlignment.Center });
                }
                lines.Children.Add(line);
            }

            var dismiss = new Button
            {
                Content = "✕", FontSize = 11, MinHeight = 22, MinWidth = 22, Padding = new Thickness(6, 0, 6, 0),
                VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(8, 0, 0, 0), ToolTip = "Dismiss this note",
            }.Styled("Hue.Button.Ghost");
            System.Windows.Automation.AutomationProperties.SetName(dismiss, "Dismiss this note");
            dismiss.Click += (_, _) => { _entries.Clear(); Render(); };

            var dock = new DockPanel { LastChildFill = true };
            DockPanel.SetDock(dismiss, Dock.Right);
            dock.Children.Add(dismiss);
            dock.Children.Add(lines);
            _note.Children.Add(dock);
            _note.Visibility = Visibility.Visible;
        }
    }
}
