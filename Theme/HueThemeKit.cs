using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using Microsoft.Win32;

namespace HueThemeKit;

// The code half of HueTheme.xaml: the two things XAML cannot do. Drop-in file; keep the
// namespace and add `using HueThemeKit;` where you call it.
//
//   App.OnStartup:        HueContrast.Follow(this);
//   each window's ctor:   InitializeComponent(); HueTitleBar.Attach(this);
//   switches that ask:    <kit:HueSwitch StateChanging="..." />, with HueConfirm.Ask(...)
//
// The class names carry the Hue prefix on purpose. C# resolves a type in the app's own
// namespace before any using, so a kit class named like an app's existing helper (a
// "DarkTitleBar", say) would be silently shadowed and the app would keep the old one.

/// <summary>
/// Hands the colours back to Windows while a contrast theme (High Contrast) is on.
///
/// Someone who has chosen a contrast theme has chosen their colours; a dark palette laid over
/// it takes that away. While one is on, this maps every theme brush to the matching system
/// colour, turns glows off and lets Windows draw the title bar. The styles stay, so layout,
/// focus rings and selection bars keep working in the user's colours. It follows the setting
/// live, including switching from one contrast theme to another.
/// </summary>
public static class HueContrast
{
    private static ResourceDictionary? _overrides;
    private static Application? _app;

    /// <summary>True while Windows has a contrast theme on.</summary>
    public static bool IsActive => SystemParameters.HighContrast;

    /// <summary>Raised on the UI thread after the brushes have been swapped either way.</summary>
    public static event EventHandler? Changed;

    public static void Follow(Application app)
    {
        if (_app is not null) return;
        _app = app;

        SystemParameters.StaticPropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SystemParameters.HighContrast)) Refresh();
        };
        // Switching from one contrast theme to another changes colours, not HighContrast.
        SystemEvents.UserPreferenceChanged += (_, e) =>
        {
            if (e.Category is UserPreferenceCategory.Color or UserPreferenceCategory.Accessibility) Refresh();
        };

        Update();
    }

    private static void Refresh() => _app?.Dispatcher.BeginInvoke(new Action(Update));

    private static void Update()
    {
        if (_app is null) return;
        var merged = _app.Resources.MergedDictionaries;

        if (_overrides is not null)
        {
            merged.Remove(_overrides);
            _overrides = null;
        }

        if (IsActive)
        {
            // Added last, so it wins over the theme and anything merged before it.
            _overrides = Build();
            merged.Add(_overrides);
        }

        foreach (Window window in _app.Windows)
            HueTitleBar.Apply(window);

        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static ResourceDictionary Build()
    {
        var window = SystemColors.WindowBrush;
        var text = SystemColors.WindowTextBrush;
        var gray = SystemColors.GrayTextBrush;
        var face = SystemColors.ControlBrush;
        var highlight = SystemColors.HighlightBrush;
        var onHighlight = SystemColors.HighlightTextBrush;

        var d = new ResourceDictionary();
        void Set(Brush brush, params string[] keys)
        {
            foreach (var key in keys) d[key] = brush;
        }

        Set(window, "Brush.Base", "Brush.Chrome", "Brush.Surface", "Brush.Hover",
            "Brush.AccentSoft", "Brush.AccentSoftHover", "Busy.Scrim", "Brush.OnStatus",
            "Brush.OkSoft", "Brush.WarnSoft", "Brush.LimitSoft", "Brush.ErrorSoft", "Brush.StaleSoft");
        Set(face, "Brush.Raised");
        Set(text, "Brush.LineSoft", "Brush.Line", "Brush.LineStrong", "Brush.ControlEdge",
            "Brush.Text", "Brush.TextDim", "Brush.TextMuted",
            "Brush.Ok", "Brush.OkText", "Brush.OkEdge", "Brush.Warn", "Brush.WarnText", "Brush.WarnEdge",
            "Brush.Limit", "Brush.LimitText", "Brush.LimitEdge", "Brush.Error", "Brush.ErrorText", "Brush.ErrorEdge",
            "Brush.Stale", "Brush.StaleText", "Brush.StaleEdge");
        Set(gray, "Brush.TextDisabled");
        Set(highlight, "Brush.Accent", "Brush.AccentMid", "Brush.AccentLight", "Brush.AccentText",
            "Brush.AccentFill", "Brush.AccentFillHover", "Brush.AccentEdge", "Brush.Glow",
            "Brush.ErrorSolid", "Brush.ErrorSolidHover", "Busy.Ring", "Busy.RingAccent");
        Set(onHighlight, "Brush.OnAccent", "Brush.OnError");

        d["Glow.Opacity"] = 0.0;
        return d;
    }
}

/// <summary>
/// A dark title bar, coloured from the theme.
///
/// Dark mode works on Windows 10 1809 and later; the caption, caption-text and border colours
/// need Windows 11 and are silently ignored on older builds, which keep the plain dark
/// caption. Colours: caption = Brush.Chrome (the title bar and the menu row read as one
/// strip), caption text = Brush.Text, border = the accent blended into Chrome. While a
/// contrast theme is on it hands the caption back to Windows. Call <see cref="Apply"/> again
/// if the brushes change at runtime.
/// </summary>
public static class HueTitleBar
{
    private const int DwmwaUseImmersiveDarkModeOld = 19;
    private const int DwmwaUseImmersiveDarkMode = 20;
    private const int DwmwaBorderColor = 34;
    private const int DwmwaCaptionColor = 35;
    private const int DwmwaTextColor = 36;
    private const int DwmwaColorDefault = unchecked((int)0xFFFFFFFF);

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);

    public static void Attach(Window window)
    {
        if (new WindowInteropHelper(window).Handle != IntPtr.Zero)
            Apply(window);
        else
            window.SourceInitialized += (_, _) => Apply(window);
    }

    public static void Apply(Window window)
    {
        var hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero) return;

        if (SystemParameters.HighContrast)
        {
            int off = 0;
            if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref off, sizeof(int)) != 0)
                DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeOld, ref off, sizeof(int));
            foreach (var attribute in new[] { DwmwaCaptionColor, DwmwaTextColor, DwmwaBorderColor })
            {
                int system = DwmwaColorDefault;
                DwmSetWindowAttribute(hwnd, attribute, ref system, sizeof(int));
            }
            return;
        }

        int on = 1;
        if (DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkMode, ref on, sizeof(int)) != 0)
            DwmSetWindowAttribute(hwnd, DwmwaUseImmersiveDarkModeOld, ref on, sizeof(int));

        var chrome = Find(window, "Brush.Chrome");
        var text = Find(window, "Brush.Text");
        var accent = Find(window, "Brush.Accent");

        if (chrome is { } c) Set(hwnd, DwmwaCaptionColor, c);
        if (text is { } t) Set(hwnd, DwmwaTextColor, t);
        if (chrome is { } bg && accent is { } fg) Set(hwnd, DwmwaBorderColor, Blend(bg, fg, 0.55));
    }

    private static Color? Find(Window window, string key) =>
        (window.TryFindResource(key) as SolidColorBrush)?.Color;

    private static void Set(IntPtr hwnd, int attribute, Color color)
    {
        int colorRef = color.R | (color.G << 8) | (color.B << 16);   // COLORREF is 0x00BBGGRR
        DwmSetWindowAttribute(hwnd, attribute, ref colorRef, sizeof(int));
    }

    private static Color Blend(Color from, Color to, double amount) => Color.FromRgb(
        (byte)Math.Round(from.R + (to.R - from.R) * amount),
        (byte)Math.Round(from.G + (to.G - from.G) * amount),
        (byte)Math.Round(from.B + (to.B - from.B) * amount));
}

/// <summary>
/// A switch whose clicks are requests, not changes: before it moves, it raises
/// <see cref="StateChanging"/>, and a handler can cancel the move, for example after asking
/// with <see cref="HueConfirm.Ask"/>. With no handler it behaves like a normal switch.
///
/// Styled with Hue.Switch. With IsThreeState="True" it is a -1 / 0 / +1 switch
/// (IsChecked false / null / true) that moves the way people expect:
///   click on the track  - to the third clicked (left = off, middle = not set, right = on)
///   click on the label  - one step along: off, not set, on, then back to off
///   Left / Right arrows - one step towards that side
///   Space               - same as clicking the label
///
/// Changes made in code (IsChecked = ..., or a binding) are not requests and are applied
/// directly; only the user's own clicks, keys and assistive-technology toggles ask first.
/// </summary>
public class HueSwitch : ToggleButton
{
    public static readonly RoutedEvent StateChangingEvent = EventManager.RegisterRoutedEvent(
        nameof(StateChanging), RoutingStrategy.Bubble, typeof(HueSwitchChangingEventHandler), typeof(HueSwitch));

    private static readonly bool?[] Order = { false, null, true };

    private FrameworkElement? _track;
    private double? _clickX;

    public HueSwitch()
    {
        SetResourceReference(StyleProperty, "Hue.Switch");
    }

    /// <summary>Raised before a user-initiated change. Set Cancel to keep the current state.</summary>
    public event HueSwitchChangingEventHandler StateChanging
    {
        add => AddHandler(StateChangingEvent, value);
        remove => RemoveHandler(StateChangingEvent, value);
    }

    public override void OnApplyTemplate()
    {
        base.OnApplyTemplate();
        _track = GetTemplateChild("Track") as FrameworkElement;
    }

    protected override void OnMouseLeftButtonUp(MouseButtonEventArgs e)
    {
        // Remember where on the track the click landed, for the duration of this click only.
        // Tested by position, not IsMouseOver: the switch captures the mouse while the button
        // is down, and under capture WPF reports IsMouseOver as false for the elements inside
        // it, the track included.
        _clickX = null;
        if (_track is { ActualWidth: > 0, ActualHeight: > 0 } track)
        {
            var p = e.GetPosition(track);
            if (p.X >= 0 && p.X <= track.ActualWidth && p.Y >= 0 && p.Y <= track.ActualHeight)
                _clickX = p.X;
        }
        try
        {
            base.OnMouseLeftButtonUp(e);
        }
        finally
        {
            _clickX = null;
        }
    }

    /// <summary>Replaces WPF's built-in "move to the next state" with a request.</summary>
    protected override void OnToggle()
    {
        if (!IsThreeState)
        {
            Request(IsChecked != true);
            return;
        }

        if (_clickX is { } x && _track is { ActualWidth: > 0 } track)
        {
            var third = track.ActualWidth / 3;
            bool? target = x < third ? false : x > 2 * third ? true : (bool?)null;
            Request(target);
            return;
        }

        Request(Order[(Array.IndexOf(Order, IsChecked) + 1) % Order.Length]);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (IsThreeState && e.Key is Key.Left or Key.Right)
        {
            var i = Array.IndexOf(Order, IsChecked) + (e.Key == Key.Right ? 1 : -1);
            if (i >= 0 && i < Order.Length) Request(Order[i]);
            e.Handled = true;
            return;
        }
        base.OnKeyDown(e);
    }

    private void Request(bool? target)
    {
        if (target == IsChecked) return;
        if (!IsThreeState && target is null) return;

        var args = new HueSwitchChangingEventArgs(StateChangingEvent, this, IsChecked, target);
        RaiseEvent(args);

        // SetCurrentValue, so a binding on IsChecked survives and receives the new value.
        if (!args.Cancel) SetCurrentValue(IsCheckedProperty, target);
    }
}

public delegate void HueSwitchChangingEventHandler(object sender, HueSwitchChangingEventArgs e);

public sealed class HueSwitchChangingEventArgs : RoutedEventArgs
{
    internal HueSwitchChangingEventArgs(RoutedEvent routedEvent, object source, bool? from, bool? to)
        : base(routedEvent, source)
    {
        From = from;
        To = to;
    }

    /// <summary>The current state: false (off, -1), null (not set, 0) or true (on, +1).</summary>
    public bool? From { get; }

    /// <summary>The state the user asked for.</summary>
    public bool? To { get; }

    /// <summary>Set to true to keep the current state. The handler may apply the change later
    /// itself (IsChecked = ...), for example once a slow or elevated operation has succeeded.</summary>
    public bool Cancel { get; set; }

    protected override void InvokeEventHandler(Delegate genericHandler, object genericTarget) =>
        ((HueSwitchChangingEventHandler)genericHandler)(genericTarget, this);
}

/// <summary>
/// A themed confirmation dialog, in place of MessageBox (which Windows draws light).
/// Cancel has the focus and answers Enter and Escape, so an unsafe change needs a deliberate
/// click or Tab to the confirm button.
/// </summary>
public static class HueConfirm
{
    /// <summary>Returns true only if the user confirms.</summary>
    /// <param name="confirmText">The action, as a verb: "Allow", "Delete", "Apply".</param>
    /// <param name="destructive">True paints the confirm button as Hue.Button.Danger.</param>
    public static bool Ask(Window? owner, string title, string message, string confirmText, bool destructive = false)
    {
        var dialog = new Window
        {
            Title = title,
            Owner = owner,
            SizeToContent = SizeToContent.WidthAndHeight,
            ResizeMode = ResizeMode.NoResize,
            ShowInTaskbar = false,
            WindowStartupLocation = owner is null ? WindowStartupLocation.CenterScreen : WindowStartupLocation.CenterOwner,
        };
        dialog.SetResourceReference(FrameworkElement.StyleProperty, "Hue.Window");
        HueTitleBar.Attach(dialog);

        var heading = new TextBlock { Text = title, TextWrapping = TextWrapping.Wrap };
        heading.SetResourceReference(FrameworkElement.StyleProperty, "Text.Heading");

        var body = new TextBlock { Text = message, TextWrapping = TextWrapping.Wrap };
        body.SetResourceReference(FrameworkElement.StyleProperty, "Text.Body");

        // A long message scrolls inside a capped area, so the buttons never leave the screen.
        // It is a tab stop only while there is something to scroll.
        var scroll = new ScrollViewer
        {
            Content = body,
            Margin = new Thickness(0, 8, 0, 0),
            MaxHeight = MessageMaxHeight(owner),
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
            IsTabStop = false,
        };
        scroll.ScrollChanged += (_, _) => scroll.IsTabStop = scroll.ScrollableHeight > 0;

        var cancel = new Button { Content = "Cancel", IsCancel = true, IsDefault = true, MinWidth = 96, Margin = new Thickness(0, 0, 10, 0) };
        var confirm = new Button { Content = confirmText, MinWidth = 96 };
        confirm.SetResourceReference(FrameworkElement.StyleProperty, destructive ? "Hue.Button.Danger" : "Hue.Button.Primary");
        confirm.Click += (_, _) => dialog.DialogResult = true;

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 24, 0, 0),
        };
        buttons.Children.Add(cancel);
        buttons.Children.Add(confirm);

        var content = new StackPanel { Width = 420 };
        content.Children.Add(heading);
        content.Children.Add(scroll);
        content.Children.Add(buttons);

        var root = new Border { Padding = new Thickness(28, 24, 28, 24), Child = content };
        root.SetResourceReference(Border.BackgroundProperty, "Brush.Surface");
        dialog.Content = root;

        dialog.Loaded += (_, _) => cancel.Focus();
        return dialog.ShowDialog() == true;
    }

    /// <summary>
    /// The tallest a dialog's message may be: 60 % of the usable height of the screen the owner
    /// is on (the primary screen's without an owner), so the buttons stay on that screen.
    /// </summary>
    internal static double MessageMaxHeight(Window? owner)
    {
        var height = SystemParameters.WorkArea.Height;
        try
        {
            var hwnd = owner is null ? IntPtr.Zero : new WindowInteropHelper(owner).Handle;
            var monitor = hwnd == IntPtr.Zero ? IntPtr.Zero : MonitorFromWindow(hwnd, MonitorDefaultToNearest);
            var info = new MonitorInfo { Size = Marshal.SizeOf<MonitorInfo>() };
            if (monitor != IntPtr.Zero && GetMonitorInfo(monitor, ref info))
            {
                // Screen pixels to WPF units, at the owner's display scaling.
                var toWpf = PresentationSource.FromVisual(owner!)?.CompositionTarget?.TransformFromDevice ?? Matrix.Identity;
                height = toWpf.Transform(new Vector(0, info.WorkBottom - info.WorkTop)).Y;
            }
        }
        catch { /* the primary screen's height */ }
        return height * 0.6;
    }

    private const uint MonitorDefaultToNearest = 2;

    [StructLayout(LayoutKind.Sequential)]
    private struct MonitorInfo
    {
        public int Size;
        public int MonitorLeft, MonitorTop, MonitorRight, MonitorBottom;
        public int WorkLeft, WorkTop, WorkRight, WorkBottom;
        public uint Flags;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [DllImport("user32.dll")]
    private static extern bool GetMonitorInfo(IntPtr monitor, ref MonitorInfo info);
}
