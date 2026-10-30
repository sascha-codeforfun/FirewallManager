using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;

namespace FirewallManager
{
    /// <summary>
    /// Sizes a window from the screen it opens on, and centres it there. Measured fresh every
    /// time a window opens; nothing is stored (no registry, no settings file).
    ///
    /// "The screen" is the active one: the screen a given window is on (the main window, for
    /// the log viewer), or else the screen under the mouse, which is where the app was just
    /// launched from. Sizes are shares of that screen's working area (without the taskbar),
    /// with a ceiling so a big monitor doesn't give a sprawling window, and a floor so the
    /// toolbars stay usable, never larger than the screen itself.
    /// </summary>
    internal static class ScreenFit
    {
        public sealed record Sizing(double WidthShare, double HeightShare,
                                  double MaxWidth,   double MaxHeight,
                                  double MinWidth,   double MinHeight);

        /// <summary>
        /// Size and centre <paramref name="w"/> on the active screen when it opens.
        /// <paramref name="contentWidth"/>, if given, is the width the window's content needs
        /// (e.g. a toolbar on one line, measured when the window opens): the window is made at
        /// least that wide, above the ceiling if need be, but never wider than the screen.
        /// </summary>
        public static void Apply(Window w, Sizing size, Window? near = null, Func<double>? contentWidth = null)
        {
            w.WindowStartupLocation = WindowStartupLocation.Manual;
            w.SourceInitialized += (_, _) =>
            {
                if (WorkArea(w, near) is not Rect area) return;          // keep the XAML size

                w.MinWidth  = Math.Min(size.MinWidth,  area.Width);
                w.MinHeight = Math.Min(size.MinHeight, area.Height);
                var width  = Math.Clamp(area.Width * size.WidthShare, size.MinWidth, size.MaxWidth);
                if (contentWidth != null)
                {
                    try { width = Math.Max(width, contentWidth()); } catch { /* keep the share */ }
                }
                width = Math.Min(width, area.Width);
                var height = Math.Min(Math.Clamp(area.Height * size.HeightShare, size.MinHeight, size.MaxHeight), area.Height);

                w.Width  = width;
                w.Height = height;
                w.Left   = area.Left + (area.Width  - width)  / 2;
                w.Top    = area.Top  + (area.Height - height) / 2;
            };
        }

        /// <summary>
        /// For dialogs that keep their own size: never taller or wider than the screen they
        /// open on (their owner's screen), with a small margin.
        /// </summary>
        public static void Cap(Window w, double margin = 40)
        {
            w.SourceInitialized += (_, _) =>
            {
                if (WorkArea(w, w.Owner) is not Rect area) return;
                w.MaxWidth  = Math.Max(200, area.Width  - margin);
                w.MaxHeight = Math.Max(200, area.Height - margin);
            };
        }

        /// <summary>The active screen's working area, in WPF units.</summary>
        private static Rect? WorkArea(Window w, Window? near)
        {
            try
            {
                var monitor = IntPtr.Zero;
                var nearHandle = near != null ? new WindowInteropHelper(near).Handle : IntPtr.Zero;
                if (nearHandle != IntPtr.Zero)
                    monitor = MonitorFromWindow(nearHandle, MONITOR_DEFAULTTONEAREST);
                else if (GetCursorPos(out var pt))
                    monitor = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);

                var info = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
                if (monitor == IntPtr.Zero || !GetMonitorInfo(monitor, ref info)) return null;

                // Screen pixels → WPF units (display scaling), via the window's own transform.
                var toWpf = PresentationSource.FromVisual(w)?.CompositionTarget?.TransformFromDevice
                            ?? Matrix.Identity;
                var topLeft     = toWpf.Transform(new Point(info.rcWork.Left,  info.rcWork.Top));
                var bottomRight = toWpf.Transform(new Point(info.rcWork.Right, info.rcWork.Bottom));
                return new Rect(topLeft, bottomRight);
            }
            catch { return null; }
        }

        // ── Win32 ───────────────────────────────────────────────────────────────

        private const uint MONITOR_DEFAULTTONEAREST = 2;

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT { public int X, Y; }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        [StructLayout(LayoutKind.Sequential)]
        private struct MONITORINFO
        {
            public int  cbSize;
            public RECT rcMonitor;
            public RECT rcWork;
            public uint dwFlags;
        }

        [DllImport("user32.dll")] private static extern bool   GetCursorPos(out POINT pt);
        [DllImport("user32.dll")] private static extern IntPtr MonitorFromPoint(POINT pt, uint flags);
        [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);
        [DllImport("user32.dll")] private static extern bool   GetMonitorInfo(IntPtr monitor, ref MONITORINFO info);
    }
}
