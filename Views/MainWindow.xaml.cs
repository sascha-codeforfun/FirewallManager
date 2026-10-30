using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Principal;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Input;

using HueThemeKit;

namespace FirewallManager
{
    public partial class MainWindow : Window
    {
        private const string RegGPO        = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";
        private const string RegLocal      = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";
        private const string RegGPOProfiles= @"SOFTWARE\Policies\Microsoft\WindowsFirewall";

        private ObservableCollection<FirewallRule>  _allRules = new();
        private ObservableCollection<FirewallRule>  _filtered = new();
        private ObservableCollection<ProfileStatus> _profiles = new();
        private bool _isAdmin;
        // Purge Local, Lock down or deleting a local rule running: each must wait for the others,
        // and none may start twice.
        private bool _busy;

        public MainWindow() : this(null) { }

        /// <param name="startup">Start-up writes held back because they could cut a Remote Desktop
        /// session: settled first, under the session guard, with the content locked until then.</param>
        internal MainWindow(StartupWrites.Pending? startup)
        {
            InitializeComponent();
            HueTitleBar.Attach(this);
            // Opens on the screen under the mouse (where the app was launched from), centred,
            // at 90% of that screen (at most 1760 × 1100, at least 1000 × 600).
            ScreenFit.Apply(this, new ScreenFit.Sizing(0.90, 0.90, 1760, 1100, 1000, 600));

            // Connection auditing: shown whenever this window comes to the front, and offered
            // off on every close of the app (the log window asks first if it's open).
            Activated += (_, _) => RefreshAuditPill();
            Closing   += MainWindow_Closing;
            WirePolicyApply();

            var os = OsInfo.Describe();
            OsTitle.Text    = os.Title;
            OsDetail.Text   = os.Detail;
            OsPanel.ToolTip = os.Tooltip;
            _catalogQuery   = os.CatalogQuery;
            _patch = new PatchScene(Stage, OsPlasters, OsTitle, Stage);
            ReadPatchAge(os.Tooltip);
            StartSweep();

            BuildVersion.Text  = $"version {BuildInfo.AppVersion}";
            BuildSdk.Text      = $"built with SDK {BuildInfo.SdkVersion}";
            BuildRuntime.Text  = $"runtime {BuildInfo.RuntimeVersion}";
            BuildPanel.ToolTip = BuildInfo.Tooltip;
            _isAdmin = IsRunningAsAdmin();
            if (!_isAdmin) AdminWarning.Visibility = Visibility.Visible;
            var gone = WindowsTools.Missing(WindowsTools.NeededByFeatures).Select(WindowsTools.Name).ToList();
            var goneText = gone.Count > 0
                ? $"Not found in {Environment.SystemDirectory}: {string.Join(", ", gone)}. The features that need them say so when used."
                : "";
            if (gone.Count > 0)
            {
                AdminWarning.Content    = "Missing: " + string.Join(", ", gone);
                AdminWarning.ToolTip    = goneText;
                AdminWarning.Visibility = Visibility.Visible;
            }
            ProfilePanel.ItemsSource = _profiles;
            ApplyRareHue();
            HueContrast.Changed += OnContrastChanged;
            Closed += (_, _) => HueContrast.Changed -= OnContrastChanged;
            // Pins: a quick size-and-date check now, full hashes in the background where needed.
            Pins.Changed += OnPinsChanged;
            Closed += (_, _) => Pins.Changed -= OnPinsChanged;
            Pins.CheckAtStart();
            LoadRules();
            if (startup != null)
            {
                // Nothing here is usable, and nothing writes, before the start-up writes are settled.
                LockContent(true);
                SetBusy(true);
                _closeBlocker = "The start-up check";
                ContentRendered += async (_, _) => await SettleStartupAsync(startup);
            }
            SizeChanged += (_, __) => ScheduleBottomLayout();
            Loaded     += (_, __) => ScheduleBottomLayout();
            Loaded     += (_, __) => FitHeader();
        }

        // ── Start-up writes under the session guard ──────────────────────────
        //  App held the seed and the StandardProfile move back (StartupWrites.CouldCut). The guard
        //  judges the facts; the app goes on only once they are written, or closes with the
        //  profile values as they were, so the next start asks again.

        private bool _settled;
        // Closing from the start-up check: "nothing is written" includes the close question.
        private bool _closingUnsettled;

        private async System.Threading.Tasks.Task SettleStartupAsync(StartupWrites.Pending p)
        {
            if (_settled) return;   // ContentRendered comes once, but only one settling ever runs
            _settled = true;

            MergeOffOutcome outcome;
            try
            {
                outcome = await MergeOffGuard.RunAsync(this, Busy, LockContent, GuardChange.StartupMove,
                                                       StartupWrites.After(p.Strays), () => StartupWrites.Write(p), ShowStateInForce);
            }
            catch (Exception ex)
            {
                outcome = new MergeOffOutcome(MergeOffResult.Refused, $"The start-up check failed: {ex.Message.TrimEnd('.')}.", true);
            }

            try
            {
            switch (outcome.Result)
            {
                case MergeOffResult.NotNeeded:
                case MergeOffResult.WithoutRule:
                    // netsh can take a while: the writes run on the overlay's worker, the dialogs after.
                    StartupWrites.Outcome written;
                    try { written = await Busy.RunAsync("Writing the start-up values", _ => StartupWrites.Collect(p)); }
                    catch (Exception ex) { written = new StartupWrites.Outcome(null, "Could not write the start-up values", $"{ex.Message}\n\nThe app closes."); }
                    if (!StartupWrites.ShowFailure(this, written)) { CloseApp(); return; }
                    Unlock();
                    LoadRules();
                    if (written.Done!.Length > 0) ApplyPolicy(written.Done);
                    return;
                case MergeOffResult.Kept:
                    // Written and applied by the guard.
                    Unlock();
                    LoadRules();
                    SetStatus(outcome.Message, GuardTone(outcome));
                    StatusText.ToolTip = outcome.Detail;
                    return;
                case MergeOffResult.Cancelled:
                    CloseApp();
                    return;
                default:
                    // PutBack or Refused. Worded from what is there now: a put-back that failed
                    // leaves the values moved, and the seed isn't in the snapshot.
                    var left      = LocalGroupPolicy.FindStrays();
                    var seedAdded = p.NeedSeed && LocalGroupPolicy.HasFirewallSetting();
                    var seedAsked = p.NeedSeed && !seedAdded;
                    var title = left.Count == 0 ? "Start-up values moved"
                              : left.Count < p.Strays.Count ? "Start-up values partly moved"
                              : "Start-up values not moved";
                    var tail = (left.Count > 0, seedAdded, seedAsked) switch
                    {
                        (true,  true, _)     => "The local Group Policy setting the app adds was kept; the next start asks only about the move.",
                        (true,  _,    _)     => "The next start asks again.",
                        (false, _,    true)  => "The values stay moved; the next start asks only about the local Group Policy setting.",
                        _                    => "The values stay moved and nothing is left to ask, so the next start doesn't ask again.",
                    };
                    // The guard shows some outcomes in a dialog of its own: said once is enough.
                    ThemedDialog.Info(this, title,
                        (outcome.Shown ? "" : $"{outcome.Message}\n\n") + $"The app closes. {tail}", danger: true);
                    CloseApp();
                    return;
            }
            }
            catch (Exception ex)
            {
                // Anything unforeseen here would leave the window locked and refusing to close.
                // The next start checks again from what is actually there.
                try
                {
                    ThemedDialog.Info(this, "Start-up check failed",
                        $"Something went wrong while finishing the start-up check: {ex.Message.TrimEnd('.')}.\n\n" +
                        "The app closes; the next start checks again.", danger: true);
                }
                catch { }
                CloseApp();
            }

            void Unlock()
            {
                _closeBlocker = null;
                SetBusy(false);
                LockContent(false);
            }

            void CloseApp()
            {
                _closeBlocker = null;
                _closingUnsettled = true;
                Application.Current.Shutdown();
            }
        }

        // ── The Windows block in the header ──────────────────────────────────
        //  Clicking it offers this machine's updates in the Microsoft Update Catalog. 30 seconds
        //  after the window becomes active, and then every 90 seconds while it stays active, a band
        //  of light glides across the block; counting starts afresh each time the window becomes active. None with a contrast theme
        //  on; Windows' animation setting (off in many Remote Desktop sessions) doesn't stop it.

        private string _catalogQuery = "";
        private System.Windows.Threading.DispatcherTimer? _sweepTimer;

        private void StartSweep()
        {
            var first = TimeSpan.FromSeconds(30);
            var timer = new System.Windows.Threading.DispatcherTimer { Interval = first };
            _sweepTimer = timer;
            timer.Tick += (_, _) => { timer.Interval = TimeSpan.FromSeconds(90); SweepOrScene(); };
            Activated   += (_, _) => { timer.Stop(); timer.Interval = first; timer.Start(); };
            Deactivated += (_, _) => { timer.Stop(); _patch?.Stop(); };
            Closed      += (_, _) => { timer.Stop(); _patch?.Stop(); };
            SizeChanged += (_, _) => _patch?.Stop();
            StateChanged += (_, _) => _patch?.Stop();
        }

        // ── Patch age ────────────────────────────────────────────────────────
        //  While the last cumulative update is a while back, plasters on the Windows name (always,
        //  at any size). On a wide window (1920 physical pixels or more) with room left of the
        //  Windows block, now and then in place of the sweep: the scene, where they get put on.

        private PatchScene? _patch;
        private PatchAge.State? _realPatch;
        private string _flickLevel = "real";   // what the plasters show: this machine, or a level picked
        private int? _sweepsSinceScene;   // null until the first scene

        private void ReadPatchAge(string osTooltip)
        {
            _ = System.Threading.Tasks.Task.Run(PatchAge.Read).ContinueWith(t =>
            {
                if (t.Status != System.Threading.Tasks.TaskStatus.RanToCompletion || _patch == null) return;
                var state = t.Result;
                _realPatch = state;
                if (_flickLevel == "real") _patch.State = state;
                if (state.LastUpdate is { } last)
                {
                    var since = state.Missed switch
                    {
                        0 => "up to date with Patch Tuesday",
                        1 => "1 Patch Tuesday since",
                        var n => $"{n} Patch Tuesdays since",
                    };
                    OsPanel.ToolTip = $"{osTooltip}\n\nLast cumulative update: {last:d} ({since}).";
                }
                if (state.DaysSinceEndOfSupport is { } days)
                    OsPanel.ToolTip = $"{OsPanel.ToolTip}\nWindows 10 support ended on {PatchAge.Windows10EndOfSupport:d}, {days} days ago.";
            }, System.Threading.Tasks.TaskScheduler.FromCurrentSynchronizationContext());
        }

        private void SweepOrScene()
        {
            if (_patch == null || _patch.Running) return;
            if ((_sweepsSinceScene is null or >= 3) && SceneDoor() is { } doorX)
            {
                _sweepsSinceScene = 0;
                _ = _patch.PlayAsync(doorX);
                return;
            }
            if (_sweepsSinceScene != null) _sweepsSinceScene++;
            Sweep();
        }

        // Where the door goes (its left edge on the stage), or null when the scene doesn't fit now.
        // Asked for (the picker's Play), the window's width and focus don't matter, the room does.
        private double? SceneDoor(bool asked = false)
        {
            if (_patch?.State is not { Behind: true }) return null;
            if (WindowState == WindowState.Minimized || HueContrast.IsActive) return null;
            if (!asked && (!IsActive || ActualWidth * System.Windows.Media.VisualTreeHelper.GetDpi(this).DpiScaleX < 1920)) return null;
            if (!OsTitle.IsVisible || !FamilyStrip.IsVisible) return null;
            // The free stretch between the status strip and the Windows block: room for the door and
            // for the sign Flick holds out to the left of the name.
            var left  = FamilyStrip.TranslatePoint(new Point(FamilyStrip.ActualWidth, 0), Stage).X + 12;
            var right = OsButton.TranslatePoint(new Point(0, 0), Stage).X - 12;
            if (right - left < PatchScene.Room) return null;
            // Clear of the sign (about 160 left of the block) where there's room; behind it where there isn't.
            return Math.Max(left + 10, right - 200 - Door.DoorWidth);
        }

        // ── Flick on request ────────────────────────────────────────────────
        //  Ctrl+click on the logo shows the level picker beside the status pills (and hides it again,
        //  back to this machine's own level): the plasters of any level, and the scene now.

        private void ToggleFlickPicker()
        {
            var show = FlickPicker.Visibility != Visibility.Visible;
            FlickPicker.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
            FitHeader();   // the strip's column keeps at least the strip's width, picker included
            if (!show) PickFlickLevel("real");
            else MarkFlickLevel();
        }

        private void FlickPick_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button { Tag: string tag } || _patch == null) return;
            if (tag != "play") { PickFlickLevel(tag); return; }
            if (_patch.Running) return;
            if (_patch.State is not { Behind: true })
            {
                SetStatus("This machine is up to date: nothing to patch. Pick a level to see one.");
                return;
            }
            if (HueContrast.IsActive) { SetStatus("The scene doesn't play with a contrast theme on."); return; }
            if (SceneDoor(asked: true) is not { } doorX)
            {
                SetStatus("Not enough room in the header for the scene: make the window wider.");
                return;
            }
            _ = _patch.PlayAsync(doorX);
        }

        private void PickFlickLevel(string level)
        {
            if (_patch == null) return;
            _flickLevel = level;
            var eol = (DateTime.Today - PatchAge.Windows10EndOfSupport).Days;
            _patch.State = level switch
            {
                "1"  => new PatchAge.State(DateTime.Today, 1, null),
                "2"  => new PatchAge.State(DateTime.Today, 2, null),
                "4"  => new PatchAge.State(DateTime.Today, 5, null),
                "10" => new PatchAge.State(DateTime.Today, 0, _realPatch?.DaysSinceEndOfSupport ?? Math.Max(1, eol)),
                _    => _realPatch,
            };
            MarkFlickLevel();
        }

        private void MarkFlickLevel()
        {
            foreach (var child in FlickPicker.Children)
                if (child is Button { Tag: string tag } b && tag != "play")
                    b.Style = (Style)FindResource(tag == _flickLevel ? "Flick.Picked" : "Flick.Pick");
        }

        private void Sweep()
        {
            if (!IsActive || WindowState == WindowState.Minimized) return;
            if (HueContrast.IsActive) return;   // colours belong to Windows then; the animation setting doesn't stop it
            var accent = (TryFindResource("Brush.AccentText") as System.Windows.Media.SolidColorBrush)?.Color
                         ?? System.Windows.Media.Colors.White;
            // The band: the accent colour, flaring to near white at its centre, about half a word wide.
            var hot = System.Windows.Media.Color.FromRgb(
                (byte)(accent.R + (255 - accent.R) * 0.75), (byte)(accent.G + (255 - accent.G) * 0.75), (byte)(accent.B + (255 - accent.B) * 0.75));
            var clear = System.Windows.Media.Color.FromArgb(0, accent.R, accent.G, accent.B);

            void Glide(TextBlock overlay, TimeSpan delay)
            {
                var shift = new System.Windows.Media.TranslateTransform(-1, 0);
                overlay.Foreground = new System.Windows.Media.LinearGradientBrush
                {
                    StartPoint = new Point(0, 0.5), EndPoint = new Point(1, 0.5),
                    RelativeTransform = shift,
                    GradientStops =
                    {
                        new System.Windows.Media.GradientStop(clear,  0.25),
                        new System.Windows.Media.GradientStop(accent, 0.40),
                        new System.Windows.Media.GradientStop(hot,    0.50),
                        new System.Windows.Media.GradientStop(accent, 0.60),
                        new System.Windows.Media.GradientStop(clear,  0.75),
                    },
                };
                shift.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty,
                    new System.Windows.Media.Animation.DoubleAnimation(-1, 1, TimeSpan.FromSeconds(1.8))
                    {
                        BeginTime = delay,
                        EasingFunction = new System.Windows.Media.Animation.SineEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseInOut },
                    });
            }

            Glide(OsSweep, TimeSpan.Zero);
            Glide(OsDetailSweep, TimeSpan.FromSeconds(0.25));   // the second line a moment later
        }

        private void OsButton_Click(object sender, RoutedEventArgs e)
        {
            var url = "https://www.catalog.update.microsoft.com/Search.aspx?q=" + Uri.EscapeDataString(_catalogQuery);
            if (!ThemedDialog.Confirm(this, "Microsoft Update Catalog",
                    $"Open the Microsoft Update Catalog in your browser, searching for {_catalogQuery}?\n\n" +
                    "It opens as you, not as administrator. On a deny-by-default machine the browser needs its own " +
                    "rule or the HTTPS switch.", "Open"))
                return;
            try
            {
                // Handed to Explorer, which opens it in the default browser as the signed-in user:
                // started directly from here, the browser would run as administrator too.
                var explorer = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe");
                Process.Start(new ProcessStartInfo(explorer, $"\"{url}\"") { UseShellExecute = false });
            }
            catch (Exception ex) { SetStatus($"The browser couldn't be started: {ex.Message.TrimEnd('.')}.", error: true); }
        }

        // ── Header status strip ───────────────────────────────────────────────
        //  Facts about this machine, no verdict: on is a plain pill, off the indigo outlier,
        //  unknown a plain "?". Never green or red.

        private void RefreshFamilyPills()
        {
            SetFamilyPill(Ipv4Pill, "IPv4", System.Net.Sockets.AddressFamily.InterNetwork);
            var v6 = SetFamilyPill(Ipv6Pill, "IPv6", System.Net.Sockets.AddressFamily.InterNetworkV6,
                                   " The Remote IPv6 column is hidden meanwhile; Export still lists it.");
            ColRemoteV6.Visibility = v6 == "off" ? Visibility.Collapsed : Visibility.Visible;
            if (IsLoaded) FitHeader();
        }

        private static string SetFamilyPill(ContentControl pill, string label, System.Net.Sockets.AddressFamily family, string whenOff = "")
        {
            var (state, interfaces) = NetworkLocality.Family(family);
            pill.Styled(state == "off" ? "Pill.Rare" : "Hue.Pill");
            pill.Content = $"{label} {(state == "unknown" ? "?" : state)}";
            pill.ToolTip = state switch
            {
                "on"  => $"{(interfaces.Count == 1 ? "This network interface has" : "These network interfaces have")} an {label} address: {string.Join(", ", interfaces)}.",
                "off" => $"No network interface that is up, other than loopback, has an {label} address.{whenOff}",
                _     => $"No network interface other than loopback is up, or the interfaces couldn't be read, so whether this machine has {label} can't be told.",
            };
            return state;
        }

        // The strip centres in the header's free middle: the title column is as wide as its text
        // and no wider, so the rest goes to the strip. When narrow, the title gives way first
        // (its description clips) and the pills keep their size.
        private void FitHeader()
        {
            var unbounded = new Size(double.PositiveInfinity, double.PositiveInfinity);
            TitlePanel.Measure(unbounded);
            FamilyStrip.Measure(unbounded);
            TitleCol.MaxWidth = TitlePanel.DesiredSize.Width;
            StripCol.MinWidth = FamilyStrip.DesiredSize.Width;
        }

        private void OnContrastChanged(object? sender, EventArgs e)
        {
            ApplyRareHue();
            _patch?.Lay();   // the plasters in the contrast theme's colours, or back; ends a scene
        }

        // Deliberate exception (see MainWindow.xaml): indigo normally, the system's own colours
        // while Windows has a contrast theme on, as the log window does for its Rare tag.
        private void ApplyRareHue()
        {
            if (HueContrast.IsActive)
            {
                Resources["Rare.Text"] = SystemColors.WindowTextBrush;
                Resources["Rare.Soft"] = SystemColors.WindowBrush;
                Resources["Rare.Edge"] = SystemColors.WindowTextBrush;
            }
            else
            {
                Resources["Rare.Text"] = Resources["Rare.Text.Hue"];
                Resources["Rare.Soft"] = Resources["Rare.Soft.Hue"];
                Resources["Rare.Edge"] = Resources["Rare.Edge.Hue"];
            }
        }

        // ── Tight-space layout ────────────────────────────────────────────────
        //  Switches to tabs when the bottom panel can't fit status and controls side by
        //  side. Measured on content, not window width: chrome and margins make the window
        //  wider than the point where the content stops fitting.
        //    available < need + 12  → tabs (just before the halves would clip)
        //    available > need + 60  → back to both (hysteresis, so it doesn't flutter)
        private bool _tabMode;
        private bool _showStatusTab;
        private bool _layoutQueued;
        private bool _applyingLayout;
        private double _bothHalvesNeed;                // cached combined desired width (roomy)
        private const double EnterMargin = 12;
        private const double LeaveBuffer = 60;

        private void ScheduleBottomLayout()
        {
            if (_layoutQueued) return;
            _layoutQueued = true;
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, new System.Action(() =>
            {
                _layoutQueued = false;
                ApplyBottomLayout();
            }));
        }

        private void ApplyBottomLayout()
        {
            if (GpoHalf == null || ControlsHalf == null || TabsFrame == null || BottomPanel == null) return;
            if (_applyingLayout) return;
            _applyingLayout = true;
            try
            {
                double available = BottomPanel.ActualWidth;

                // Measured only while both halves show: a collapsed half measures 0.
                if (!_tabMode)
                {
                    GpoHalf.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                    ControlsHalf.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));
                    var need = GpoHalf.DesiredSize.Width + ControlsHalf.DesiredSize.Width;
                    if (need > 0) _bothHalvesNeed = need;
                }

                // Hysteresis on content overflow.
                if (!_tabMode && available > 0 && available < _bothHalvesNeed + EnterMargin) _tabMode = true;
                else if (_tabMode && available > _bothHalvesNeed + LeaveBuffer)              _tabMode = false;

                if (!_tabMode)
                {
                    GpoHalf.Visibility      = Visibility.Visible;
                    ControlsHalf.Visibility = Visibility.Visible;
                    GpoCol.Width            = new GridLength(1, GridUnitType.Star);
                    TabsFrame.Visibility    = Visibility.Collapsed;
                }
                else
                {
                    // The tabs get a row of their own under the status line, which stays in view.
                    TabsFrame.Visibility = Visibility.Visible;
                    if (_showStatusTab)
                    {
                        GpoHalf.Visibility      = Visibility.Visible;
                        ControlsHalf.Visibility = Visibility.Collapsed;
                        GpoCol.Width            = new GridLength(1, GridUnitType.Star);
                    }
                    else
                    {
                        GpoHalf.Visibility      = Visibility.Collapsed;
                        ControlsHalf.Visibility = Visibility.Visible;
                        GpoCol.Width            = new GridLength(0);
                    }
                    TabStatus.IsChecked   = _showStatusTab;
                    TabControls.IsChecked = !_showStatusTab;
                }
            }
            finally { _applyingLayout = false; }
        }

        private void TabStatus_Checked(object sender, RoutedEventArgs e)
        {
            if (!_tabMode) return;
            _showStatusTab = true;
            ApplyBottomLayout();
        }

        private void TabControls_Checked(object sender, RoutedEventArgs e)
        {
            if (!_tabMode) return;
            _showStatusTab = false;
            ApplyBottomLayout();
        }

        // ── Models ───────────────────────────────────────────────────────────

        public class FirewallRule : INotifyPropertyChanged
        {
            public string RegistryKey   { get; set; } = "";
            public string RegistryPath  { get; set; } = "";
            private string _name = "";
            private string? _resolvedName;
            public string Name { get => _name; set { _name = value; _nameView = null; } }
            // Windows' readable text for a "@file,-id" name, or null. Display only: the reference
            // is what is stored, backed up and exported.
            public string? ResolvedName { get => _resolvedName; set { _resolvedName = value; _nameView = null; } }
            public string? NameTip => NameView.Tip;
            // Display-only: strip the redundant CUSTOM prefix. Raw Name/RegistryKey keep it.
            public string NameDisplay => NameView.Display;

            // Names and paths come from Windows and other tools, so hidden characters and
            // look-alike letters are shown, not passed on: ⚠ in the cell, the findings in the
            // tooltip. Display only: exports and backups keep the stored text, and search finds both.
            private (string Display, string? Tip)? _nameView;
            private (string Display, string? Tip) NameView => _nameView ??= MakeNameView();
            private (string, string?) MakeNameView()
            {
                var n = RuleWriter.Plain(ResolvedName ?? Name);
                var display  = TextHygiene.Reveal(n);
                var findings = new List<string>(display.Findings);
                // One of the app's own rules whose stored name lacks CUSTOM (an early version made
                // it): Windows' own tools can't tell where it came from. Shown, not changed.
                if (Source == "GPO-Script" && RuleWriter.NameUnmarked(RegistryKey, Name))
                    findings.Add($"Stored as \"{Name}\", without CUSTOM: Windows' own tools (wf.msc, gpedit) " +
                                 "can't tell this rule came from FirewallManager. Edit and save to add it.");
                if (ResolvedName == null) return Marked(display.Shown, null, findings);
                var stored = TextHygiene.Reveal(Name);
                findings.AddRange(stored.Findings.Where(f => !findings.Contains(f)));
                return Marked(display.Shown, stored.Shown, findings);
            }

            private static (string, string?) Marked(string shown, string? tip, List<string> findings) =>
                findings.Count == 0
                    ? (shown, tip)
                    : ("⚠ " + shown, (tip != null ? tip + "\n\n" : "") + string.Join("\n", findings));

            public string Direction     { get; set; } = "";
            public string Action        { get; set; } = "";
            public string Protocol      { get; set; } = "";
            public string ProtocolTip   => Protocols.Tip(Protocol);
            // Ports as stored: RPort = the other side's port (Out rules), LPort = this machine's
            // port (In rules). Shown by direction; the Dir column says which side it is.
            public string RemotePorts   { get; set; } = "";
            public string LocalPorts    { get; set; } = "";
            // Local / Remote / Mixed / Any: is the remote address on this machine's networks?
            public string Locality      { get; set; } = "";
            public string LocalityTip   { get; set; } = "";
            // Coloured on Allow rules only: how far an opening reaches. A Block rule's reach is
            // how much it shuts, so there the tag stays neutral.
            public string LocalityTone => Action == "Allow" ? NetworkLocality.Tone(Locality) : "";
            public string Ports => Direction == "In"
                ? (LocalPorts.Length  > 0 ? LocalPorts  : RemotePorts)
                : (RemotePorts.Length > 0 ? RemotePorts : LocalPorts);
            // RA4 and RA6 as stored, each family on its own and never merged: "Any" when the rule
            // has neither field, "none" when it has only the other family's.
            public string RemoteV4      { get; set; } = "";
            public string RemoteV6      { get; set; } = "";
            /// <summary>The rule editor's reading: the IPv4 list, else the IPv6 one marked "IPv6:", else Any.</summary>
            public string RemoteAddress { get; set; } = "";
            public const string NoneWord = "none";
            private static string NoneTip(string family) =>
                $"No {family} address in this rule. Shown as none: whether Windows applies the rule to {family} at all isn't verified yet.";
            /// <summary>The full IPv4 list, and the exact span of each subnet or range in it.</summary>
            public string? RemoteTip => RemoteV4 == NoneWord ? NoneTip("IPv4")
                : Ipv4Scope.Describe(RemoteV4) is { Length: > 0 } span
                ? $"{RemoteV4}\n\n{span}"
                : RemoteV4.Length > 28 ? RemoteV4 : null;
            public string? RemoteV6Tip => RemoteV6 == NoneWord ? NoneTip("IPv6")
                : RemoteV6.Length > 28 ? RemoteV6 : null;
            private string _program = "", _service = "";
            public string Program { get => _program; set { _program = value; _programView = null; } }  // full path
            public string Service { get => _service; set { _service = value; _programView = null; } }  // Svc=: the one service inside svchost.exe
            public string ProgramDisplay => ProgramView.Display;

            // What goes in front of the program (ProgramIcons): Windows' icon for it, or one of the
            // app's own (a service's stand-in, a program that isn't there, one not checked).
            private ProgramLook? _look;
            public ProgramLook? Look
            {
                get => _look;
                set
                {
                    if (Equals(_look, value)) return;
                    _look = value;
                    RaiseProgram();
                }
            }

            // What the program file is (ProgramTrust): Windows' own, signed, pinned, not signed, or
            // an off case. Colours the name; a broken signature or a changed pin also takes over the icon.
            private ProgramVerdict? _verdict;
            public ProgramVerdict? Verdict
            {
                get => _verdict;
                set
                {
                    if (Equals(_verdict, value)) return;
                    _verdict = value;
                    RaiseProgram();
                }
            }

            private void RaiseProgram()
            {
                foreach (var name in new[] { nameof(ProgramImage), nameof(ProgramGlyph), nameof(ProgramAlert), nameof(ProgramAlertRed),
                                             nameof(ProgramIconTip), nameof(ProgramTone), nameof(ProgramTip) })
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
            }

            // The icon's own alert (program or service missing, not a full path) comes first: it
            // says the rule can't match at all. Then the verdict's (signature, pin).
            private bool LookAlerts => _look?.Alert == true;
            private bool VerdictAlerts => !LookAlerts && _verdict?.Icon != null;

            public System.Windows.Media.ImageSource? ProgramImage => VerdictAlerts ? null : _look?.Image;
            public System.Windows.Media.Geometry? ProgramGlyph =>
                (VerdictAlerts ? "Icon.Alert" : _look?.Glyph) is { } key
                    ? Application.Current?.TryFindResource(key) as System.Windows.Media.Geometry : null;
            /// <summary>Drawn in the warning colour: the program or service isn't there or can't match, or the file is an off case.</summary>
            public bool ProgramAlert => LookAlerts || VerdictAlerts;
            /// <summary>Drawn in red: the file no longer matches the user's pin.</summary>
            public bool ProgramAlertRed => VerdictAlerts && _verdict!.Icon == "Error";
            public string? ProgramIconTip => VerdictAlerts ? _verdict!.Tip : _look?.Tip;
            /// <summary>The fingerprint after the name: none when not pinned, else its state (see PinMark).</summary>
            private PinMark _pinMark;
            public PinMark PinMark
            {
                get => _pinMark;
                set
                {
                    if (_pinMark == value) return;
                    _pinMark = value;
                    PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(PinMark)));
                }
            }

            /// <summary>The name's colour (see ProgramTone); the normal text colour while not known.</summary>
            public ProgramTone ProgramTone => _verdict?.Tone ?? ProgramTone.None;
            /// <summary>The path, anything hidden in it, and what is known about the file.</summary>
            public string? ProgramTip =>
                string.Join("\n\n", new[] { ProgramView.Tip, _verdict?.Tip }.Where(t => !string.IsNullOrEmpty(t))) is { Length: > 0 } tip
                    ? tip : null;

            private (string Display, string? Tip)? _programView;
            private (string Display, string? Tip) ProgramView => _programView ??= MakeProgramView();
            private (string, string?) MakeProgramView()
            {
                if (string.IsNullOrEmpty(Program)) return ("", null);
                var path     = TextHygiene.Reveal(Program);
                var file     = TextHygiene.Reveal(System.IO.Path.GetFileName(Program)).Shown;
                var findings = new List<string>(path.Findings);
                if (string.IsNullOrEmpty(Service)) return Marked(file, path.Shown, findings);
                var service = TextHygiene.Reveal(Service);
                findings.AddRange(service.Findings.Where(f => !findings.Contains(f)));
                return Marked($"{file} ({service.Shown})", path.Shown, findings);
            }

            // svchost.exe alone is no scope: it hosts dozens of services. With Svc= it is one.
            public bool  ProgramScoped => !string.IsNullOrEmpty(Program)
                && !(System.IO.Path.GetFileName(Program).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
                     && string.IsNullOrEmpty(Service));
            public string Active        { get; set; } = "";
            public string Source        { get; set; } = "";
            public string RawValue      { get; set; } = "";

            // As Windows reads it: on unless Active=FALSE (a rule without the field is on).
            public bool  ActiveBool => RuleText.IsOn(RawValue);

            // Scoped = tied to a fixed address (anything but Any: single IPs, ranges, subnets)
            // or to a fixed program. An Allow rule with neither is a blanket open, in either
            // direction: amber. Block rules are never flagged. Any on one family is open there.
            public bool  IsBlanket => Action == "Allow"
                                      && (RemoteV4 == "Any" || RemoteV6 == "Any") && !ProgramScoped;

            // Colours for the row (state dot, source/direction/action tags, active pill)
            // are chosen in MainWindow.xaml from ActiveBool, Source, Direction and Action.

            public event PropertyChangedEventHandler? PropertyChanged;
            public void Refresh() => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(""));
        }

        public enum Safety { Safe, Unsafe, Unset }

        /// <summary>
        /// The fingerprint after a pinned program's name: at rest (light grey), being hashed now
        /// (amber), matched in this session (green), changed since pinned (red).
        /// </summary>
        public enum PinMark { None, Rest, Checking, Matched, Changed }

        // One editable firewall setting. It tracks safety, not the raw DWORD, so an
        // all-green tile reads as a fully hardened profile.
        public class ProfileToggle : INotifyPropertyChanged
        {
            public string Label     { get; set; } = "";
            public string Profile   { get; set; } = "";   // Domain / Private / Public
            public string RegValue  { get; set; } = "";   // EnableFirewall, etc.
            public int    SafeDword { get; set; }          // the DWORD that means "safe"
            public string SafeWord  { get; set; } = "";    // e.g. "ON" / "Block" / "No"
            public string UnsafeWord{ get; set; } = "";    // e.g. "OFF" / "Allow" / "Yes"
            public System.Collections.Generic.List<string> RegKeys { get; set; } = new(); // target subkeys

            private Safety _state;
            public Safety State
            {
                get => _state;
                set { _state = value;
                      OnChanged(nameof(State)); OnChanged(nameof(SwitchState));
                      OnChanged(nameof(ValueText)); }
            }

            // For the kit's signal switch (Hue.Switch.SafeWhenOn): safe = on, unsafe = off,
            // never set = null (knob centred). The switch picks its colour from this.
            public bool? SwitchState => _state switch
            {
                Safety.Safe   => true,
                Safety.Unsafe => false,
                _             => null,
            };
            public string ValueText => _state switch
            {
                Safety.Safe   => SafeWord,
                Safety.Unsafe => UnsafeWord,
                _             => "Not configured",   // a word, not a dash: the kit's rule for signal switches
            };

            public event PropertyChangedEventHandler? PropertyChanged;
            private void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
        }

        public class ProfileStatus
        {
            public string ProfileName { get; set; } = "";
            public System.Collections.Generic.List<ProfileToggle> Toggles { get; set; } = new();
        }

        // ── Loading ──────────────────────────────────────────────────────────

        // Before a Keep countdown: the tiles and the list show what is in force, and the status
        // line keeps the result it shows (the reload's own count line would replace it).
        private void ShowStateInForce()
        {
            LoadRules(reportCount: false);
            RefreshAuditPill();
        }

        private void LoadRules(bool reportCount = true)
        {
            _allRules.Clear();
            NetworkLocality.Refresh();   // this machine's networks, for the Network column
            RefreshFamilyPills();
            LoadFromRegistry(RegGPO,   isGPO: true);
            LoadFromRegistry(RegLocal, isGPO: false);
            LoadProfileStatus();
            ApplyFilter();
            ShowProgramIcons();
            RefreshQuickButtons();
            RefreshPurgeButton();
            RefreshDnsClientButton();
            if (!reportCount) return;
            SetStatus($"Loaded {_allRules.Count} {RulesWord(_allRules.Count)}  —  " +
                      $"{_allRules.Count(r => r.Source == "GPO-Script")} GPO-Script  " +
                      $"{_allRules.Count(r => r.Source == "GPO-Manual")} GPO-Manual  " +
                      $"{_allRules.Count(r => r.Source == "Local")} Local");
        }

        // What is already known shows at once; the rest is looked up in the background and fills
        // in when it arrives, so the list never waits for it.
        private void ShowProgramIcons()
        {
            foreach (var rule in _allRules)
            {
                rule.Look    = ProgramIcons.For(rule.Program, rule.Service, out _);
                rule.Verdict = ProgramTrust.For(rule.Program);
            }
            ProgramIcons.Load(_allRules.Select(r => (r.Program, r.Service)).ToList(), () =>
            {
                foreach (var rule in _allRules) rule.Look = ProgramIcons.For(rule.Program, rule.Service, out _);
            });
            ProgramTrust.Load(_allRules.Select(r => r.Program).ToList(), ShowVerdicts);
            ShowFingerprintButton();
        }

        // A background pin check finished: show it, and say so when a pinned file changed.
        private void OnPinsChanged() => Dispatcher.InvokeAsync(() =>
        {
            ShowVerdicts();
            var changed = _allRules.Where(r => r.ProgramTone == ProgramTone.Mismatch)
                                   .Select(r => System.IO.Path.GetFileName(r.Program)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            if (changed.Count > 0 && !_busy)
                SetStatus($"Changed since pinned: {string.Join(", ", changed)}.", error: true);
        });

        // Signatures and pins as known now; also after a pin check finished in the background.
        private void ShowVerdicts()
        {
            foreach (var rule in _allRules)
            {
                rule.Verdict = ProgramTrust.For(rule.Program);
                rule.PinMark = PinMarkOf(rule);
            }
            ShowFingerprintButton();
        }

        // The file being hashed right now by the fingerprint button, by pin key; null when none.
        private string? _hashing;
        private bool _pinCheckRunning;

        private PinMark PinMarkOf(FirewallRule rule)
        {
            if (ProgramTrust.PathOf(rule.Program) is not { } path) return PinMark.None;
            var pin = Pins.For(path);
            if (pin.State == Pins.State.None) return PinMark.None;
            if (_hashing != null && Pins.Key(path).Equals(_hashing, StringComparison.OrdinalIgnoreCase)) return PinMark.Checking;
            return pin.State switch
            {
                Pins.State.Checking => PinMark.Checking,
                Pins.State.Mismatch => PinMark.Changed,
                Pins.State.Missing  => PinMark.Rest,   // the program icon says it's gone
                _ when Pins.CheckedThisSession(path) => PinMark.Matched,
                _ => PinMark.Rest,
            };
        }

        // Hidden without pins. Amber until every pin was hashed in this session, red while one
        // doesn't match, green once all did: an app opened only now and then asks for the check.
        private void ShowFingerprintButton()
        {
            if (!Pins.Any) { BtnCheckPins.Visibility = Visibility.Collapsed; return; }
            BtnCheckPins.Visibility = Visibility.Visible;
            var (key, tip) = Pins.AnyMismatch
                ? ("Brush.ErrorText", "A pinned program changed since it was pinned. Click to check all pinned programs again.")
                : Pins.Paths().All(Pins.CheckedThisSession)   // every pin hashed and matched in this session
                    ? ("Brush.OkText", "All pinned programs were checked in this session and match. Click to check again.")
                    : ("Brush.WarnText", "Pinned programs not fully checked in this session. Click to check their fingerprints (SHA-256).");
            PinsIcon.SetResourceReference(System.Windows.Shapes.Shape.StrokeProperty, key);
            BtnCheckPins.ToolTip = tip;
        }

        // The fingerprint button in the Program header: every pinned file hashed now, one after
        // another, in plain view. A file takes at least a quarter second, so the sequence can be
        // followed even where hashing takes a millisecond; a large one takes what it takes. Rules
        // for the same file change together, and the file is hashed once.
        private static readonly TimeSpan PinStep = TimeSpan.FromMilliseconds(250);

        private async void BtnCheckPins_Click(object sender, RoutedEventArgs e)
        {
            if (_pinCheckRunning) return;
            _pinCheckRunning = true;
            BtnCheckPins.IsEnabled = false;
            var changed = new List<string>();
            try
            {
                // In the order the list shows them, then any pinned file no rule names.
                var pinned = Pins.Paths();
                var order = _filtered.Select(r => ProgramTrust.PathOf(r.Program)).OfType<string>().Select(Pins.Key)
                                     .Concat(pinned)
                                     .Where(k => pinned.Contains(k, StringComparer.OrdinalIgnoreCase))
                                     .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                SetStatus($"Checking {order.Count} pinned program{(order.Count == 1 ? "" : "s")}…");
                foreach (var file in order)
                {
                    _hashing = file;
                    ShowPinMarks();
                    var started = DateTime.UtcNow;
                    Pins.State state;
                    try { state = await System.Threading.Tasks.Task.Run(() => Pins.CheckOne(file)); }
                    catch { state = Pins.State.None; }
                    var rest = PinStep - (DateTime.UtcNow - started);
                    if (rest > TimeSpan.Zero) await System.Threading.Tasks.Task.Delay(rest);
                    if (state == Pins.State.Mismatch) changed.Add(System.IO.Path.GetFileName(file));
                    _hashing = null;
                    ShowVerdicts();
                }
            }
            catch (Exception ex) { SetStatus($"Pin check error: {ex.Message}", error: true); }
            finally
            {
                _hashing = null;
                _pinCheckRunning = false;
                BtnCheckPins.IsEnabled = true;
                ShowVerdicts();
            }
            SetStatus(changed.Count == 0
                ? "Pinned programs checked: all match."
                : $"Pinned programs checked: {changed.Count} changed since pinned: {string.Join(", ", changed)}.", error: changed.Count > 0);
        }

        private void ShowPinMarks()
        {
            foreach (var rule in _allRules) rule.PinMark = PinMarkOf(rule);
        }

        private void LoadFromRegistry(string path, bool isGPO)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(path, writable: false);
                if (key == null) return;
                // Every value is a rule: one that isn't shows as an unreadable row, never hidden.
                foreach (var name in key.GetValueNames())
                {
                    var raw = key.GetValue(name)?.ToString() ?? "";
                    _allRules.Add(ParseRule(name, raw, path, isGPO));
                }
            }
            catch (UnauthorizedAccessException)
            {
                SetStatus($"Access denied reading {(isGPO ? "GPO" : "Local")} rules.", error: true);
            }
        }

        private void LoadProfileStatus()
        {
            _profiles.Clear();

            // Three tiles, never merged even when identical: the toggles carry settings, so
            // each profile must stay editable on its own.
            // Policy key names only. "StandardProfile" is the pre-Vista name that Windows
            // ignores for these settings; the start-up check moves values found there.
            _profiles.Add(ReadProfile("Domain",  "DomainProfile"));
            _profiles.Add(ReadProfile("Private", "PrivateProfile"));
            _profiles.Add(ReadProfile("Public",  "PublicProfile"));
            RefreshMergeState();
        }

        // A missing key (nothing set yet) is also where the switches write.
        private ProfileStatus ReadProfile(string label, string regKey)
        {
            int fw = -1, inb = -1, outb = -1, mrg = -1;
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey($@"{RegGPOProfiles}\{regKey}");
                if (k != null)
                {
                    fw   = ReadDword(k, "EnableFirewall", -1);
                    inb  = ReadDword(k, "DefaultInboundAction", -1);
                    outb = ReadDword(k, "DefaultOutboundAction", -1);
                    mrg  = ReadDword(k, "AllowLocalPolicyMerge", -1);
                }
            }
            catch { /* unreadable: shown as not configured */ }

            var keys = new System.Collections.Generic.List<string> { regKey };
            ProfileToggle Mk(string lbl, string val, int safe, string sw, string uw, int raw) => new()
            {
                Label = lbl, Profile = label, RegValue = val, SafeDword = safe, SafeWord = sw, UnsafeWord = uw,
                RegKeys = keys,
                State = raw == -1 ? Safety.Unset : (raw == safe ? Safety.Safe : Safety.Unsafe)
            };

            return new ProfileStatus
            {
                ProfileName = label,
                Toggles =
                {
                    Mk("Firewall", "EnableFirewall",        1, "ON",    "OFF",   fw),
                    Mk("Inbound",  "DefaultInboundAction",  1, "Block", "Allow", inb),
                    Mk("Outbound", "DefaultOutboundAction", 1, "Block", "Allow", outb),
                    Mk("Merge",    "AllowLocalPolicyMerge", 0, "No",    "Yes",   mrg),
                }
            };
        }

        // The switch only asks; this applies. Its own move is always cancelled so the state
        // changes only once the registry write has succeeded (State → SwitchState → binding).
        private async void ProfileToggle_StateChanging(object sender, HueSwitchChangingEventArgs e)
        {
            e.Cancel = true;
            if (sender is not FrameworkElement { DataContext: ProfileToggle t }) return;
            try { await ApplyProfileToggle(t); }
            catch (Exception ex)
            {
                // Shows what the registry holds now, whatever the failure left.
                LoadProfileStatus();
                SetStatus($"Couldn't change {t.Label}: {ex.Message}", error: true);
            }
        }

        // What is running that closing would cut off halfway (Lock down, Purge Local, the merge-off
        // guard), as the status line names it; null when nothing is.
        private string? _closeBlocker;

        private async System.Threading.Tasks.Task ApplyProfileToggle(ProfileToggle t)
        {
            // Lock down, a purge or the merge-off guard is running: they save and put back the
            // firewall state, which a write in between would spoil.
            if (_busy) { SetStatus("Wait until the current task is done."); return; }

            // Unset and Unsafe both go to Safe (pinning the secure value). Only Safe → Unsafe
            // opens the firewall, so only that asks first.
            bool goingUnsafe = t.State == Safety.Safe;
            int newDword = goingUnsafe ? (t.SafeDword == 1 ? 0 : 1) : t.SafeDword;
            var newState = goingUnsafe ? Safety.Unsafe : Safety.Safe;

            if (goingUnsafe)
            {
                var msg = $"This sets {t.Label} to “{t.UnsafeWord}” on {t.Profile}.\n\n" +
                          $"That moves away from the locked-down default. It writes Group Policy " +
                          $"and applies it (gpupdate). Continue?";
                if (!ThemedDialog.Confirm(this, "Open a firewall default?", msg, "Set " + t.UnsafeWord, danger: true))
                    return;
            }

            // Merge off, inbound block and firewall on can each leave only the operator's own rules
            // letting Remote Desktop in; outbound block can end the program that carries a session
            // over a VPN. The guard judges from the facts whether this one does; for the first three
            // it offers a rule for the client first, with the failsafe, and writes the change itself.
            GuardChange? change = goingUnsafe ? null : t.RegValue switch
            {
                "AllowLocalPolicyMerge" => GuardChange.MergeOff,
                "DefaultInboundAction"  => GuardChange.InboundBlock,
                "EnableFirewall"        => GuardChange.FirewallOn,
                "DefaultOutboundAction" => GuardChange.OutboundBlock,
                _                       => null,
            };
            if (change is { } guarded)
            {
                // The write runs on the guard's worker: plain copies, nothing bound to the window.
                var keys  = t.RegKeys.ToArray();
                var value = t.RegValue;
                var after = new List<ProfileAfter>
                {
                    new(t.Profile,
                        value == "EnableFirewall"        ? newDword : null,
                        value == "DefaultInboundAction"  ? newDword : null,
                        value == "AllowLocalPolicyMerge" ? newDword : null,
                        value == "DefaultOutboundAction" ? newDword : null),
                };
                MergeOffOutcome outcome;
                SetBusy(true);
                _closeBlocker = $"{GuardWords.Of(guarded).Change} over Remote Desktop";
                try
                {
                    outcome = await MergeOffGuard.RunAsync(this, Busy, LockContent, guarded, after,
                        () => WriteProfileValue(keys, value, newDword, written: null), ShowStateInForce);
                }
                finally
                {
                    _closeBlocker = null;
                    SetBusy(false);
                }

                switch (outcome.Result)
                {
                    case MergeOffResult.Kept:
                    case MergeOffResult.PutBack:
                        // Written and applied (or put back) by the guard: only the display follows.
                        LoadRules();
                        SetStatus(outcome.Message, GuardTone(outcome));
                        StatusText.ToolTip = outcome.Detail;
                        return;
                    case MergeOffResult.Cancelled:
                        LoadProfileStatus();
                        SetStatus(outcome.Message);
                        return;
                    case MergeOffResult.Refused:
                        SetStatus(outcome.Message, error: true);
                        return;
                }
                // NotNeeded or WithoutRule: written as usual.
            }

            var done = new List<string>();
            try
            {
                WriteProfileValue(t.RegKeys, t.RegValue, newDword, done);
            }
            catch (Exception ex)
            {
                LoadProfileStatus();
                SetStatus($"Couldn't write {t.Label}: {ex.Message.TrimEnd('.')}. " +
                          (done.Count == 0 ? "Nothing was changed."
                                           : $"Written for {string.Join(", ", done)} only, not applied (gpupdate)."), error: true);
                return;
            }
            t.State = newState;
            LoadProfileStatus();
            ApplyPolicy($"{t.Profile} {t.Label} → {t.ValueText}");
        }

        /// <summary>
        /// One profile setting written to each of its policy keys. Throws if a key can't be opened
        /// or written. Touches no control, so the merge-off guard runs it on its worker. Each key
        /// written goes into <paramref name="written"/>, so a failure can say what was changed.
        /// </summary>
        private static void WriteProfileValue(IEnumerable<string> subkeys, string value, int dword, List<string>? written)
        {
            foreach (var subkey in subkeys)
            {
                using var k = Registry.LocalMachine.CreateSubKey($@"{RegGPOProfiles}\{subkey}")
                              ?? throw new InvalidOperationException($"{subkey} in the firewall policy could not be opened for writing");
                k.SetValue(value, dword, RegistryValueKind.DWord);
                written?.Add(subkey);
            }
        }

        private static int ReadDword(RegistryKey? k, string name, int fallback)
            => k?.GetValue(name) is int v ? v : fallback;

        // ── Parsing ──────────────────────────────────────────────────────────

        private static FirewallRule ParseRule(string regKey, string raw, string regPath, bool isGPO)
        {
            var rule = new FirewallRule
            {
                RegistryKey  = regKey,
                RegistryPath = regPath,
                RawValue     = raw,
                Source       = !isGPO ? "Local" : regKey.StartsWith("CUSTOM_") ? "GPO-Script" : "GPO-Manual"
            };

            var ra4 = new List<string>();
            var ra6 = new List<string>();
            foreach (var part in raw.Split('|'))
            {
                if (!part.Contains('=')) continue;
                var idx = part.IndexOf('=');
                var k   = part[..idx].Trim().ToUpperInvariant();
                var v   = part[(idx+1)..].Trim();
                switch (k)
                {
                    case "NAME":     rule.Name      = v; break;
                    case "DIR":      rule.Direction = v; break;
                    case "ACTION":   rule.Action    = v; break;
                    case "ACTIVE":   rule.Active    = v.ToUpperInvariant(); break;
                    case "APP":      rule.Program   = v; break;
                    case "SVC":      rule.Service   = v; break;
                    case "PROTOCOL": rule.Protocol  = Protocols.Name(v); break;
                    case "RPORT":    rule.RemotePorts = rule.RemotePorts.Length == 0 ? v : rule.RemotePorts + "," + v; break;
                    case "LPORT":    rule.LocalPorts  = rule.LocalPorts.Length  == 0 ? v : rule.LocalPorts  + "," + v; break;
                    case "RA4":      ra4.Add(v); break;
                    case "RA6":      ra6.Add(v); break;
                }
            }

            if (string.IsNullOrEmpty(rule.Name)) rule.Name = regKey;
            rule.ResolvedName = IndirectNames.Resolve(rule.Name);
            // Whether a rule with only one family's field applies to the other family at all is
            // not verified, so the other side reads "none" rather than a guess.
            var neither = ra4.Count == 0 && ra6.Count == 0;
            rule.RemoteV4 = ra4.Count > 0 ? string.Join(",", ra4) : neither ? "Any" : FirewallRule.NoneWord;
            rule.RemoteV6 = ra6.Count > 0 ? string.Join(",", ra6) : neither ? "Any" : FirewallRule.NoneWord;
            rule.RemoteAddress = ra4.Count > 0 ? rule.RemoteV4
                               : ra6.Count > 0 ? string.Join(",", ra6.SelectMany(a => a.Split(',')).Select(a => "IPv6:" + a.Trim()))
                               : "Any";
            // Windows writes "any protocol" by leaving the field out.
            if (string.IsNullOrEmpty(rule.Protocol)) rule.Protocol = "Any";
            var where = rule.RemoteV4 == FirewallRule.NoneWord
                ? new NetworkLocality.Result("None", "No IPv4 address in the rule.")
                : NetworkLocality.ClassifyRule(rule.RemoteV4);
            rule.Locality    = where.Kind;
            rule.LocalityTip = where.Tip + "\n\nJudged on the IPv4 addresses only.";
            return rule;
        }

        // ── Filtering ────────────────────────────────────────────────────────

        private void ApplyFilter()
        {
            if (SearchBox == null || FilterCombo == null) return;
            var search = SearchBox.Text.Trim();
            var filter = (FilterCombo.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "All Rules";

            var result = _allRules.AsEnumerable();
            result = filter switch
            {
                "Enabled Only"    => result.Where(r => r.ActiveBool),
                "Disabled Only"   => result.Where(r => !r.ActiveBool),
                "Inbound Only"    => result.Where(r => r.Direction == "In"),
                "Outbound Only"   => result.Where(r => r.Direction == "Out"),
                "Allow Only"      => result.Where(r => r.Action == "Allow"),
                "Block Only"      => result.Where(r => r.Action == "Block"),
                "GPO-Script Only" => result.Where(r => r.Source == "GPO-Script"),
                "GPO-Manual Only" => result.Where(r => r.Source == "GPO-Manual"),
                "Local Only"      => result.Where(r => r.Source == "Local"),
                _                 => result
            };

            // Culture-neutral: the machine's language must not change what a search finds (Turkish I).
            bool Has(string? field) => field?.Contains(search, StringComparison.OrdinalIgnoreCase) == true;
            if (!string.IsNullOrEmpty(search))
                result = result.Where(r =>
                    Has(r.Name)     || Has(r.ResolvedName) || Has(r.NameDisplay) ||
                    Has(r.RemoteV4) || Has(r.RemoteV6)     || Has(r.Program)     ||
                    Has(r.Ports)    || Has(r.Source));

            _filtered = new ObservableCollection<FirewallRule>(result);
            if (RulesGrid != null) RulesGrid.ItemsSource = _filtered;
            if (CountText != null) CountText.Text = $"{_filtered.Count} / {_allRules.Count} {RulesWord(_allRules.Count)}";
        }

        // ── Toggle ───────────────────────────────────────────────────────────

        private async System.Threading.Tasks.Task ToggleSelected(bool enable)
        {
            if (!_isAdmin)
            {
                ThemedDialog.Info(this, "Access Denied",
                    "Administrator privileges required to modify rules.", danger: true);
                return;
            }
            if (RulesGrid.SelectedItem is not FirewallRule rule || rule.Source is "GPO-Manual" or "Local") return;
            if (_busy) { SetStatus("Wait until the current task is done."); return; }

            var newVal = RuleText.WithActive(rule.RawValue, enable)
                .Replace("v2.30|", "v2.33|")
                .Replace("v2.31|", "v2.33|")
                .Replace("v2.32|", "v2.33|");
            if (!await RuleChangeAllowed(new RuleRemoval(new[] { rule.RegistryKey },
                    new Dictionary<string, string?> { [rule.RegistryKey] = newVal }))) return;
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(rule.RegistryPath, writable: true);
                if (key == null) { SetStatus("Cannot open registry key for writing.", error: true); return; }

                key.SetValue(rule.RegistryKey, newVal, RegistryValueKind.String);
                rule.RawValue = newVal;
                rule.Active   = enable ? "TRUE" : "FALSE";
                rule.Refresh();

                SetStatus($"{(enable?"Enabled":"Disabled")}: {ShownName(rule)}");
                ApplyRuleChange(rule, $"{(enable?"Enabled":"Disabled")}: {ShownName(rule)}");
                ApplyFilter();

                // ApplyFilter rebuilt the collection: reselect the rule if it still passes the
                // filter, and refresh the button here, since SelectionChanged doesn't fire when
                // the row stays selected.
                if (_filtered.Contains(rule))
                    RulesGrid.SelectedItem = rule;
                UpdateToggleButtonState(RulesGrid.SelectedItem as FirewallRule);
            }
            catch (Exception ex) { SetStatus($"Error: {ex.Message}", error: true); }
        }

        // ── Events ───────────────────────────────────────────────────────────

        private void BtnRefresh_Click(object s, RoutedEventArgs e)
        {
            ProgramIcons.Clear();   // a program installed or removed since shows as it is now
            ProgramTrust.Clear();   // and signed, replaced or updated since
            LoadRules();
        }

        private void Logo_Click(object sender, MouseButtonEventArgs e)
        {
            if ((Keyboard.Modifiers & ModifierKeys.Control) != 0) { ToggleFlickPicker(); return; }
            new ConsentWindow(reviewMode: true) { Owner = this }.ShowDialog();
        }

        private void BtnExportRules_Click(object s, RoutedEventArgs e)
        {
            var dlg = new Microsoft.Win32.SaveFileDialog
            {
                Title      = "Export Rule List",
                Filter     = "Text file (*.txt)|*.txt",
                FileName   = $"firewall-rules-{DateTime.Now:yyyyMMdd-HHmm}.txt",
                DefaultExt = ".txt"
            };
            if (dlg.ShowDialog() != true) return;

            try
            {
                var sb = new System.Text.StringBuilder();
                sb.AppendLine($"Firewall Rule Manager {BuildInfo.AppVersion} — Rule Export");
                sb.AppendLine($"Exported : {DateTime.Now:yyyy-MM-dd HH:mm}");
                sb.AppendLine($"Filter   : {(FilterCombo.SelectedItem as ComboBoxItem)?.Content}");
                sb.AppendLine($"Total    : {_filtered.Count} / {_allRules.Count} {RulesWord(_allRules.Count)}");
                sb.AppendLine();
                // Names as stored: a "@file,-id" reference reads the same in every language.
                sb.AppendLine($"{"St",-4} {"Source",-12} {"Name",-35} {"Dir",-5} {"Action",-7} {"Proto",-10} {"Port(s)",-10} {"Active",-9} {"Remote IPv4",-40} {"Remote IPv6",-40} {"Program"}");
                sb.AppendLine(new string('-', 200));

                foreach (var r in _filtered)
                {
                    sb.AppendLine($"{(r.ActiveBool ? "ON" : "off"),-4} {r.Source,-12} {r.Name,-35} {r.Direction,-5} {r.Action,-7} {r.Protocol,-10} {r.Ports,-10} {(r.Active.Length > 0 ? r.Active : "(not set)"),-9} {r.RemoteV4,-40} {r.RemoteV6,-40} {r.Program}");
                }

                sb.AppendLine();
                sb.AppendLine("--- Raw Registry Values ---");
                foreach (var r in _filtered)
                {
                    sb.AppendLine($"{r.RegistryKey}");
                    sb.AppendLine($"  {r.RawValue}");
                }

                System.IO.File.WriteAllText(dlg.FileName, sb.ToString(), System.Text.Encoding.UTF8);
                SetStatus($"Exported {_filtered.Count} {RulesWord(_filtered.Count)} → {System.IO.Path.GetFileName(dlg.FileName)}");
            }
            catch (Exception ex) { SetStatus($"Export error: {ex.Message}", error: true); }
        }
        // ── Lock down ─────────────────────────────────────────────────────────
        //  For a fresh machine: one click to a safe state. Over Remote Desktop the client gets a
        //  rule first and the user proves a new connection works; without that, the saved state
        //  comes back (this window after 180 s, a scheduled task after 360 s if the app is gone).
        //  At the console a connected client is someone else's session: no rule, no failsafe.

        private const int KeepSeconds = 180, BackstopSeconds = 360;
        // While policy is still being applied and checked (gpupdate and the check can take
        // minutes on a slow machine), the backstop must not fire before the countdown even starts.
        private const int BackstopWhileApplying = 900;

        // Disabled for the whole run, from the first click: a second click while the first one
        // still reads the connections would start a second lock-down, whose "before" snapshot is
        // the locked-down state, so its restore would put back the wrong state.
        private async void BtnLockdown_Click(object s, RoutedEventArgs e)
        {
            if (_busy) return;
            SetBusy(true);
            _closeBlocker = "Lock down";
            try { await LockdownAsync(); }
            finally
            {
                _holdPolicyResult = false;
                _closeBlocker = null;
                SetBusy(false);
            }
        }

        private async System.Threading.Tasks.Task LockdownAsync()
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }
            // The restore needs the firewall's own export and import; without netsh there is none.
            if (WindowsTools.NotFound(WindowsTools.Tool.Netsh, "the firewall state can't be saved and put back, so nothing was changed") is { } noNetsh)
            {
                SetStatus($"Not locked down: {noNetsh}.", error: true);
                return;
            }
            // Without schtasks a still-armed failsafe task can't be seen, and none can be armed.
            if (WindowsTools.NotFound(WindowsTools.Tool.Schtasks, "whether a failsafe task is still armed can't be checked, and none can be armed, so nothing was changed") is { } noSchtasks)
            {
                SetStatus($"Not locked down: {noSchtasks}.", error: true);
                return;
            }

            var existing = Lockdown.Inspect();
            var remote   = Lockdown.IsRemoteSession();
            // The ports the service listens on now, else its setting: a changed setting takes
            // effect only when the service restarts, and clients, tunnel and adapters are all read
            // over the same ports. Each client's rule names the port(s) it is connected on.
            var ports    = await System.Threading.Tasks.Task.Run(() =>
                Lockdown.RdpListeningPorts() is { Count: > 0 } listening ? listening : new List<int> { Lockdown.RdpPort() });
            var connected = await System.Threading.Tasks.Task.Run(() =>
            {
                var on = new Dictionary<string, List<int>>();
                foreach (var p in ports)
                {
                    if (Lockdown.RdpClients(p) is not { } here) return null;
                    foreach (var c in here)
                    {
                        if (!on.TryGetValue(c, out var list)) on[c] = list = new List<int>();
                        list.Add(p);
                    }
                }
                return on;
            });
            var clients  = connected?.Keys.ToList();
            // At the console this session can't be cut; the others are only named, so an
            // unreadable table stops a lock-down only in a remote session.
            if (clients == null && remote)
            {
                SetStatus("Not locked down: the machine's connections could not be read, so a Remote Desktop session can't be ruled out.", error: true);
                return;
            }
            var ruleFor  = remote ? clients! : new List<string>();
            // Policy rules stay, so a session one of yours lets in isn't ended. A rule that can't
            // be judged counts as none, as in the session guard.
            var others   = remote || clients == null ? new List<string>()
                : await System.Threading.Tasks.Task.Run(() => clients.Where(c =>
                  {
                      try { return !ports.Any(p => Lockdown.OwnRuleAllowsRdp(c, p)); }
                      catch { return true; }
                  }).ToList());
            var from     = string.Join(", ", ruleFor);
            var failsafe = ruleFor.Count > 0;
            var domain   = Lockdown.DomainJoined();
            // The names Apply writes; one already there is overwritten, so it is named as such.
            var ruleNames = ruleFor.Select(c =>
                                   {
                                       var name = Lockdown.RdpRuleName(c, ruleFor);
                                       return name + Lockdown.ReplaceNote(name, c, connected![c][0]);
                                   })
                                   .ToList();

            // How the session comes in, in a remote session: a tunnel on a Remote Desktop port (a
            // connection from this machine itself), and a VPN or tunnel adapter under a network
            // client's connection. Unreadable: nothing can be ruled out.
            var tunnel = new List<int>();
            var vpn    = new List<string>();
            if (remote)
            {
                var (tunnelRead, vpnRead) = await System.Threading.Tasks.Task.Run(() =>
                    (Lockdown.RdpTunnelPorts(ports), Lockdown.RdpVpnAdapters(ports)));
                if (vpnRead == null)
                {
                    SetStatus("Not locked down: the machine's connections could not be read, so a session over a VPN can't be ruled out.", error: true);
                    return;
                }
                if (tunnelRead == null)
                {
                    SetStatus("Not locked down: the machine's connections could not be read, so a Remote Desktop session can't be ruled out.", error: true);
                    return;
                }
                (tunnel, vpn) = (tunnelRead, vpnRead);
            }

            // Remote, but not over a connection the firewall sees on the RDP port: a Hyper-V
            // enhanced session (safe), a tunnel, or RDP through a gateway or another port (not safe).
            if (!failsafe && remote)
            {
                while (true)
                {
                    var answer = ThemedDialog.YesNoCancel(this, "Remote session without an RDP connection",
                        $"This session is remote, but no network connection on the Remote Desktop {(ports.Count == 1 ? "port" : "ports")} " +
                        $"({string.Join(", ", ports)}) was found. " +
                        (tunnel.Count > 0
                            ? MergeOffGuard.TunnelFact(tunnel) + "\n\n"
                            : "That is normal in a Hyper-V enhanced session, which doesn't go through the network. If you came in " +
                              "over the network some other way (a gateway, a forwarded port), the lock-down will cut you off.\n\n") +
                        $"With failsafe: no rule is added, but you confirm within {KeepSeconds} s or the firewall is put back.",
                        yesText: "With failsafe", noText: "Without failsafe");
                    if (answer == null) return;
                    if (answer == true) { failsafe = true; break; }
                    // Without failsafe through a tunnel: the last question first; reconsidered = ask again.
                    if (tunnel.Count == 0 || MergeOffGuard.LockDownLastChance(this, tunnel, new List<string>(), failsafe: false))
                    {
                        failsafe = false;
                        break;
                    }
                }
            }

            // The lock-down blocks outbound, which ends the program that carries a session over a
            // VPN or tunnel adapter; the app can't know that program, so only the last question,
            // asked once the failsafe is decided so the screen says whether there is one.
            if (vpn.Count > 0 && !MergeOffGuard.LockDownLastChance(this, new List<int>(), vpn, failsafe))
            {
                SetStatus("Not locked down.");
                return;
            }

            // Another person's session is ended by the lock-down: that is said even on a fresh machine.
            if (!existing.Fresh || domain || others.Count > 0)
            {
                static string N(int n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";
                var msg =
                    (existing.Fresh ? "" : $"This machine already has firewall policy: {N(existing.PolicyRules, "rule")} and {N(existing.ProfileSettings, "profile setting")}.\n\n") +
                    (existing.LocalRuleCount > 0
                        ? "Lock down sets all three profiles to block inbound and outbound with merge off, deletes " +
                          $"Windows' {N(existing.LocalRuleCount, "local rule")} and turns on recording (connection audit, DNS log, " +
                          "process starts). Your existing policy rules stay.\n\n"
                        : "Lock down sets all three profiles to block inbound and outbound with merge off and turns on recording " +
                          "(connection audit, DNS log, process starts). There are no local rules to delete. Your existing policy rules stay.\n\n") +
                    (ruleFor.Count > 0 ? $"You are connected over Remote Desktop from {from}: " +
                                         (ruleFor.Count == 1 ? "a rule for that is" : "rules for that are") +
                                         $" written first: {string.Join(", ", ruleNames)}. You confirm a new connection within {KeepSeconds} s, " +
                                         "or the firewall is put back.\n\n" : "") +
                    // Rules from outside the app aren't judged, so the end of those sessions is stated with that condition.
                    (others.Count == 1 ? $"A Remote Desktop session from {others[0]} is connected; it isn't this one (this session isn't over normal RDP). Nothing created in this app " +
                                         "lets it in, so Lock down ends it unless a rule from outside the app does grant the connection.\n\n"
                     : others.Count > 1 ? $"Remote Desktop sessions from {JoinWords(others)} are connected; they aren't this one (this session isn't over normal RDP). Nothing created " +
                                          "in this app lets them in, so Lock down ends them unless a rule from outside the app does grant the connections.\n\n"
                     : "") +
                    (domain ? "This machine is in a domain. With outbound blocked it can't reach the domain controller, so " +
                              "policy refreshes, and putting the firewall back, may only take effect after a restart.\n\n" : "") +
                    "The current state is saved first and can be put back.";
                if (!ThemedDialog.Confirm(this, "Lock down this machine?", msg, "Lock down", danger: true)) return;
            }

            // From the first write on, Lock down's result line is its own (see OnPolicyCompleted);
            // the reset is in BtnLockdown_Click's finally.
            _holdPolicyResult = true;
            SetStatus("Locking down…");

            // The work runs on a worker under the overlay and touches no control (that keeps the
            // rings turning); what it finds is drawn on the window once the overlay is down.
            var backstopAt = DateTime.Now.AddSeconds(BackstopWhileApplying);
            string? snapshot = null;
            Dictionary<string, string>? localBefore = null;
            string? notLocked = null;
            string? failedPartWay = null;
            var armedBefore = false;
            var armedUnsure = false;
            string? valuesAfter = null;
            Lockdown.PutBackResult? undo = null;
            Lockdown.Result? result = null;
            PolicyApply.Result? applied = null;
            LocalRules.Removal? removal = null;
            Exception? removalFailed = null;

            await Covered(() => Busy.RunAsync<object?>("Locking down", async report =>
            {
                // A task still armed from earlier: arming would replace it (its saved state lost), and
                // without a failsafe it would later put its older state back over the lock-down.
                if (Lockdown.BackstopState() is var there && there != false) { armedBefore = true; armedUnsure = there == null; return null; }

                report.Say("Saving the current state…");
                try { (snapshot, localBefore) = Lockdown.Snapshot(); }
                catch (Exception ex) { notLocked = $"Not locked down: the current state could not be saved ({ex.Message})."; return null; }

                if (failsafe)
                {
                    try { Lockdown.ArmBackstop(snapshot, backstopAt); }
                    catch (Exception ex)
                    {
                        // A creation that timed out may have left the task anyway: it would put
                        // the saved state back over whatever is done meanwhile.
                        notLocked = $"Not locked down: {ex.Message.TrimEnd('.')}." +
                                    (Lockdown.DisarmBackstop() ? "" :
                                     $" The failsafe task may exist anyway and could not be confirmed removed: if \"{Lockdown.BackstopTask}\" " +
                                     $"is in Task Scheduler, delete it, or it puts the saved state back at {backstopAt:HH:mm:ss}.");
                        return null;
                    }
                }

                report.Say("Writing the lock-down policy…");
                try { result = Lockdown.Apply(ruleFor.Select(c => (c, (IReadOnlyList<int>)connected![c])).ToList()); }
                catch (Exception ex)
                {
                    failedPartWay = $"Lock-down failed part way ({ex.Message})";
                    undo = await Lockdown.PutBackAsync(snapshot, failedPartWay, failsafe, t => report.Say(t));
                    return null;
                }

                var what = "Locked down" +
                           (ruleFor.Count > 0 ? $", Remote Desktop from {from} allowed" : "") +
                           $" (saved state: {snapshot} and its .wfw)" +
                           (result.LoggingProblems.Count > 0 ? $"; could not switch on: {string.Join(", ", result.LoggingProblems)}" : "");
                report.Say("Applying the policy (gpupdate) and checking that the firewall applies it…");
                applied = await PolicyApply.RunAsync(what, result.RdpRules);
                // Read once gpupdate is done: a Group Policy may rewrite a value there, and only a
                // change after this point means the failsafe task put the old state back.
                valuesAfter = LockdownValues(result.RdpRules);

                // Windows' local rules go only once the lock-down is in force (merge off applied), so
                // there is no moment in which Remote Desktop is allowed by neither the old rules nor the new ones.
                if (!applied.InForce) return null;

                // The removal can take minutes: the failsafe's deadline moves past it, so it can't
                // restore halfway through and have the rest of the removal undo its import.
                if (failsafe)
                {
                    var later = DateTime.Now.AddSeconds(BackstopWhileApplying);
                    try { Lockdown.ArmBackstop(snapshot, later); backstopAt = later; }
                    catch { }
                }
                report.Say($"Removing Windows' local rules{(localBefore is { Count: > 0 } before ? $" ({before.Count})" : "")}…");
                try { removal = Lockdown.RemoveLocal(localBefore); }
                catch (Exception ex) { removalFailed = ex; }
                return null;
            }));

            if (armedBefore)
            {
                var text = (armedUnsure, failsafe) switch
                {
                    (true, true) => $"Not locked down: whether the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier " +
                                    "lock-down or rule can't be told (Task Scheduler gave no clear answer), so it isn't replaced. Nothing was written.",
                    (true, false) => $"Not locked down: whether the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier " +
                                     "lock-down or rule can't be told (Task Scheduler gave no clear answer); if it is, it puts its saved state " +
                                     "back over the lock-down. Nothing was written.",
                    (false, true) => $"Not locked down: the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier " +
                                     "lock-down or rule, so it isn't replaced. Nothing was written.",
                    _ => $"Not locked down: the failsafe task \"{Lockdown.BackstopTask}\" is still armed from an earlier " +
                         "lock-down or rule, and it puts its saved state back over the lock-down. Nothing was written.",
                };
                SetStatus(text, error: true);
                ThemedDialog.Info(this, "Failsafe task still armed", text, danger: true);
                return;
            }
            if (notLocked != null) { SetStatus(notLocked, error: true); return; }
            if (failedPartWay != null) { ShowUndo(undo!, domain, snapshot!, failedPartWay); return; }

            // A rule Windows didn't load lets nobody in: nothing to test, nothing to keep.
            var ours    = result!.RdpRules.Select(k => k["CUSTOM_".Length..]).ToList();
            var refused = applied!.Rejected?.Where(r => ours.Contains(r, StringComparer.OrdinalIgnoreCase)).ToList() ?? new List<string>();
            if (refused.Count > 0)
            {
                var why = $"Lock-down not kept: Windows refused {JoinWords(refused)}";
                Lockdown.PutBackResult? back = null;
                await Covered(() => Busy.RunAsync<object?>("Putting the firewall back", async report =>
                {
                    back = await Lockdown.PutBackAsync(snapshot!, why, failsafe, t => report.Say(t));
                    return null;
                }));
                ShowUndo(back!, domain, snapshot!, why);
                return;
            }

            LoadRules();
            RefreshQuickButtons();
            RefreshAuditPill();
            // Green only for a lock-down in force with nothing that went wrong (recording that
            // couldn't be switched on, local rules left); the line is kept for Keep below.
            string finalLine;
            Tone finalTone;
            if (applied.InForce)
            {
                if (removalFailed != null)
                {
                    finalLine = $"{applied.Summary} Removing Windows' local rules failed ({removalFailed.Message}); some may be left. Purge Local removes the rest.";
                    finalTone = Tone.Error;
                }
                else
                {
                    finalLine = $"{applied.Summary} {LocalRemovalText(removal!)}.";
                    finalTone = applied.IsProblem || result.LoggingProblems.Count > 0 || removal!.NotRemoved.Count > 0 ? Tone.Error : Tone.InForce;
                }
                SetStatus(finalLine, finalTone);
            }
            else
            {
                var why = applied.Problem != null ? "isn't confirmed in force" : "isn't in force";
                finalLine = $"{applied.Summary} Windows' local rules were left in place while the lock-down {why}; " +
                            "Purge Local removes them once it is.";
                finalTone = Tone.Error;
                SetStatus(finalLine, finalTone);
                StatusText.ToolTip = applied.Detail;
            }
            if (!failsafe) return;

            // The countdown starts now, so the backstop moves to now as well. If moving fails,
            // the first one stays armed at its original time.
            var moved = DateTime.Now.AddSeconds(BackstopSeconds);
            try { await System.Threading.Tasks.Task.Run(() => Lockdown.ArmBackstop(snapshot!, moved)); backstopAt = moved; }
            catch { }

            // Not in force yet, a reconnect (or this session going on) proves nothing: the countdown says so.
            var notYet = applied.InForce ? "" :
                $"{applied.Summary}\n\n" +
                (applied.Problem != null ? "Whether the firewall applies it couldn't be checked" : "The firewall doesn't apply all of it yet");
            var who = ruleFor.Count > 0
                ? $"You are connected over Remote Desktop from {from}. The lock-down is in place, with " +
                  (ruleFor.Count > 1 ? "rules that let those addresses in" : "a rule that lets that address in") + ".\n\n" +
                  (applied.InForce ? "Disconnect and reconnect now. If the new connection works, click Keep."
                                   : $"{notYet}, so a reconnect now may not test the {(ruleFor.Count > 1 ? "rules" : "rule")}.")
                : $"This is a remote session without a network connection on the Remote Desktop {(ports.Count == 1 ? "port" : "ports")}. The lock-down is in place.\n\n" +
                  (applied.InForce ? "If you can still work in this session, click Keep."
                                   : $"{notYet}, so this session still working now may not test it.");
            var win = new LockdownCountdownWindow(this, who, KeepSeconds, backstopAt);
            win.ShowDialog();
            if (win.Kept)
            {
                var task = await System.Threading.Tasks.Task.Run(Lockdown.RemoveBackstop);
                // The rule list is reloaded first: loading writes its own status line, which would
                // otherwise replace this result.
                LoadRules();
                string? problem = null;
                if (LockdownValues(result.RdpRules) != valuesAfter)
                    problem = "Keep came too late: the failsafe had already put the firewall back as it was.";
                else if (task == null)
                    problem = "Lock-down kept, but whether the failsafe task is gone couldn't be told (Task Scheduler gave no clear answer). " +
                              $"If \"{Lockdown.BackstopTask}\" is in Task Scheduler, delete it, or it will put the old firewall back.";
                else if (task == true)
                    problem = $"Lock-down kept, but the failsafe task could not be removed. Delete \"{Lockdown.BackstopTask}\" in Task Scheduler, or it will put the old firewall back.";

                if (problem == null)
                {
                    // A problem the lock-down's line showed stays in view after Keep.
                    if (finalTone == Tone.Error)
                        SetStatus($"Lock-down kept. The failsafe task is removed. {finalLine}", Tone.Error);
                    else
                        SetStatus("Lock-down kept. The failsafe task is removed.", finalTone);
                }
                else
                {
                    // The status line is the next action's to overwrite; this one must be seen.
                    SetStatus(problem, error: true);
                    ThemedDialog.Info(this, "Lock-down", problem, danger: true);
                }
            }
            else
            {
                const string notConfirmed = "Lock-down not confirmed";
                Lockdown.PutBackResult? u = null;
                await Covered(() => Busy.RunAsync<object?>("Putting the firewall back", async report =>
                {
                    u = await Lockdown.PutBackAsync(snapshot!, notConfirmed, failsafe, t => report.Say(t));
                    return null;
                }));
                ShowUndo(u!, domain, snapshot!, notConfirmed);
            }
        }

        // The lock-down as it stands in policy: the profile values and its Remote Desktop rules.
        private static string LockdownValues(IEnumerable<string> ruleKeys)
        {
            var parts = new List<string>();
            using (var root = Registry.LocalMachine.OpenSubKey(RegGPOProfiles))
                foreach (var profile in new[] { "DomainProfile", "PrivateProfile", "PublicProfile" })
                {
                    using var k = root?.OpenSubKey(profile);
                    foreach (var v in new[] { "EnableFirewall", "DefaultInboundAction", "DefaultOutboundAction", "AllowLocalPolicyMerge" })
                        parts.Add(k?.GetValue(v)?.ToString() ?? "-");
                }
            using (var rules = Registry.LocalMachine.OpenSubKey(RegGPO))
                foreach (var r in ruleKeys) parts.Add(rules?.GetValue(r) as string ?? "-");
            return string.Join("|", parts);
        }

        // "a, b and c"
        private static string JoinWords(IReadOnlyList<string> parts) =>
            parts.Count <= 1 ? string.Join("", parts) : $"{string.Join(", ", parts.Take(parts.Count - 1))} and {parts[^1]}";

        // What putting the saved state back (Lockdown.PutBackAsync) found, drawn on the window,
        // in the words every failsafe uses (Lockdown.PutBackText), the domain fact added.
        private void ShowUndo(Lockdown.PutBackResult u, bool domain, string snapshot, string why)
        {
            var (text, error, detail) = Lockdown.PutBackText(u, snapshot, why);
            // In a domain the lock-down blocks the domain controller, which the refresh needs.
            if (domain && u.RestoreError == null && u.LocalProblem == null && u.Check is { InForce: false })
                text += " In a domain, the refresh needs the domain controller, which the lock-down blocks: a restart applies it.";
            // Reloading writes its own status line, so the result is set after it.
            if (u.RestoreError == null)
            {
                LoadRules();
                RefreshQuickButtons();
            }
            // Not an error after a check means the old state is in force again.
            SetStatus(text, error ? Tone.Error : u.Check is { InForce: true } ? Tone.InForce : Tone.Normal);
            StatusText.ToolTip = detail;
        }

        private void BtnServiceRules_Click(object s, RoutedEventArgs e) => new ServiceHardeningWindow(this).Show();

        private void BtnSetup_Click  (object s, RoutedEventArgs e)
        {
            if (RefuseWhileBusy()) return;
            var win = new SetupWindow { Owner = this };
            win.ShowDialog();
            LoadRules();
        }

        private LogViewerWindow? _logWindow;

        // ── Connection auditing: status and the close question ─────────────────

        private void RefreshAuditPill()
        {
            var (success, failure) = LiveDropSource.AuditState();
            string style, text, tip;
            if (success == null || failure == null)
            {
                style = "Hue.Pill.Stale"; text = "Auditing ?";
                tip = "Couldn't read whether connection auditing is on.";
            }
            else if (success == true || failure == true)
            {
                style = "Hue.Pill.Warn";
                text  = success == true && failure == true ? "Auditing on (all)"
                      : failure == true                    ? "Auditing on"
                                                           : "Auditing on (allowed)";
                tip = "Windows is writing " +
                      (success == true && failure == true ? "blocked and allowed" : failure == true ? "blocked" : "allowed") +
                      " connections to the Security log (what the log window's Live mode reads). " +
                      "It keeps doing so after this app closes. Closing the app offers to switch it off.";
            }
            else
            {
                style = "Hue.Pill"; text = "Auditing off";
                tip = "Windows isn't recording connections in the Security log. The log window's Live mode offers to turn it on.";
            }
            AuditPill.Styled(style);
            AuditPill.Content = text;
            AuditPill.ToolTip = tip;

            // The firewall's text log is superseded by Live, so its pill shows only while on.
            var (textBlocked, textAllowed) = FirewallTextLog.State();
            var textOn = textBlocked == true || textAllowed == true;
            TextLogPill.Visibility = textOn ? Visibility.Visible : Visibility.Collapsed;
            TextLogPill.ToolTip = "The firewall's text log (pfirewall.log) is recording " +
                (textBlocked == true && textAllowed == true ? "blocked and allowed" : textBlocked == true ? "blocked" : "allowed") +
                " connections. Live records the same with program names. Closing the app offers to switch it off.";

            var starts = ProcessStartLog.IsOn();
            ProcStartsPill.Visibility = starts == true ? Visibility.Visible : Visibility.Collapsed;
            ProcStartsPill.ToolTip = "Windows records every program start with its command line (Security log), " +
                "also across a restart — armed for the next boot. Closing the app offers to switch it off.";

            var dns = DnsClientLog.IsOn();
            DnsLogPill.Styled(dns == true ? "Hue.Pill.Warn" : dns == null ? "Hue.Pill.Stale" : "Hue.Pill");
            DnsLogPill.Content = dns == true ? "DNS log on" : dns == null ? "DNS log ?" : "DNS log off";
            DnsLogPill.ToolTip = dns == true
                ? "Windows is recording every DNS lookup (name, answers, program). It keeps doing so after this app closes. Closing the app offers to switch it off."
                : dns == null
                ? "Couldn't read whether Windows' DNS client log is on."
                : "Windows isn't recording DNS lookups. The log window's \"DNS log\" button switches it on.";
        }

        // One question, on closing the app: switch off whatever is still recording (connection
        // auditing, the DNS log, the firewall's text log), or keep it on for a longer watch.
        // Not asked when only the log window closes: the status pills here still show it.
        private void MainWindow_Closing(object? sender, System.ComponentModel.CancelEventArgs e)
        {
            // Closing ends the app, and a running service purge with it: cut off halfway, its report lost.
            if (ServiceHardeningWindow.AnyPurging)
            {
                e.Cancel = true;
                SetStatus("A service purge is running; the app can close when it's done.");
                return;
            }
            // Cut off halfway, a failsafe is left to the scheduled task with nobody asked to Keep,
            // and a purge to whatever part of it had run.
            if (_closeBlocker != null)
            {
                e.Cancel = true;
                SetStatus($"{_closeBlocker} is running; the app can close when it's done.");
                return;
            }
            if (_closingUnsettled) return;
            if (_logWindow is { IsVisible: true }) _logWindow.Close();
            LogViewerWindow.OfferLoggingOff(this, audit: true, dns: true, textLog: true);
        }

        private void BtnLogging_Click(object s, RoutedEventArgs e)
        {
            if (_logWindow == null || !_logWindow.IsVisible)
            {
                _logWindow = new LogViewerWindow();
                // No Owner — independent window
                _logWindow.Show();
            }
            else
            {
                _logWindow.Activate();
            }
        }

        private void SearchBox_TextChanged(object s, TextChangedEventArgs e)      => ApplyFilter();
        private void FilterCombo_SelectionChanged(object s, SelectionChangedEventArgs e) => ApplyFilter();

        private void RulesGrid_SelectionChanged(object s, SelectionChangedEventArgs e)
        {
            var rule      = RulesGrid.SelectedItem as FirewallRule;
            var canEdit   = rule != null && _isAdmin;

            BtnEditRule.IsEnabled   = canEdit;
            BtnCopyRule.IsEnabled   = canEdit;
            RefreshDeleteButton(rule);

            UpdateToggleButtonState(rule);
        }

        // With merge on, Windows' local rules count and programs add them back as they install:
        // deleting one there is the same theatre as Purge Local, so it follows the same check.
        private void RefreshDeleteButton(FirewallRule? rule)
        {
            var mergeOn = rule?.Source == "Local" ? MergeOnProfiles() : new List<string>();
            BtnDeleteRule.IsEnabled = rule != null && _isAdmin && rule.Source != "GPO-Manual" && mergeOn.Count == 0;
            // Imposed rules: say where they're managed, even on the disabled buttons.
            BtnDeleteRule.ToolTip = rule?.Source == "GPO-Manual" ? "Managed in Group Policy, not by this app — delete it there"
                                  : mergeOn.Count > 0             ? LocalDeleteNeedsMergeOff(mergeOn)
                                  : "Delete the selected rule";
        }

        private static string LocalDeleteNeedsMergeOff(IEnumerable<string> mergeOn) =>
            $"Deleting a local rule needs merge off on all three profiles. Merge is on for: {string.Join(", ", mergeOn)} (not configured counts as on).";

        // Also called after a toggle: the row stays selected, so SelectionChanged doesn't
        // fire and the button would otherwise show the pre-toggle state.
        private void UpdateToggleButtonState(FirewallRule? rule)
        {
            var canToggle = rule != null && _isAdmin && rule.Source is not ("GPO-Manual" or "Local");
            if (canToggle)
            {
                BtnToggleRule.IsEnabled  = true;
                BtnToggleRule.ToolTip    = null;   // the label says what a click does
                if (rule!.ActiveBool) IconText.Set(BtnToggleRule, "Icon.Close", "Disable");
                else                   IconText.Set(BtnToggleRule, "Icon.Check", "Enable");
                // Enabling is the step forward (tonal); disabling is plain — the label says which.
                BtnToggleRule.Styled(rule.ActiveBool ? "Hue.Button" : "Hue.Button.Tonal");
            }
            else
            {
                BtnToggleRule.IsEnabled  = false;
                BtnToggleRule.ToolTip    = rule?.Source switch
                {
                    "GPO-Manual" => "Managed in Group Policy, not by this app — enable or disable it there",
                    "Local"      => "Windows' own rule: view, copy or delete it; with merge off it doesn't apply",
                    _            => rule != null ? "Administrator required" : "Enable or disable the selected rule",
                };
                IconText.Set(BtnToggleRule, "Icon.Check", "Enable");
                BtnToggleRule.Styled("Hue.Button");
            }
        }

        private async void BtnToggleRule_Click(object s, RoutedEventArgs e)
        {
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            try { await ToggleSelected(!rule.ActiveBool); }
            catch (Exception ex) { SetStatus($"Error: {ex.Message}", error: true); }
        }

        /// <summary>
        /// Before one of the app's own rules is switched, deleted or rewritten: the session guard
        /// (RuleRemoved), which asks only when the change cuts the current Remote Desktop client.
        /// True when the change may be written; otherwise the status line says why.
        /// </summary>
        private async System.Threading.Tasks.Task<bool> RuleChangeAllowed(RuleRemoval removal)
        {
            MergeOffOutcome outcome;
            SetBusy(true);
            _closeBlocker = "The rule check";
            try { outcome = await MergeOffGuard.RuleRemovalAsync(this, Busy, LockContent, removal); }
            finally
            {
                _closeBlocker = null;
                SetBusy(false);
            }
            if (outcome.CallerMergesOff) return true;
            SetStatus(outcome.Message, error: outcome.Error || outcome.Result == MergeOffResult.Refused);
            return false;
        }

        // ── Quick toggle buttons ──────────────────────────────────────────────

        // Windows 10 and Server 2019 cope with outbound DNS blocked; on builds 22000 and up
        // (Windows 11, Server 2025) parts of the system can stop working, so there DNS off asks first.
        private static readonly bool DnsOffIsUnsafe = GetWindowsBuild() >= 22000;

        private const string QuickKeyPath = @"SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules";

        private static string? QuickRule(string ruleKey)
        {
            using var key = Registry.LocalMachine.OpenSubKey(QuickKeyPath, writable: false);
            return key?.GetValue(ruleKey)?.ToString();
        }

        // A click reads the rule before it asks or writes anything. A registry that can't be read
        // (no access, a broken key) stops the click there, as the refresh shows "?" for it.
        private bool QuickRead(string label, string ruleKey, out string? raw)
        {
            try { raw = QuickRule(ruleKey); return true; }
            catch (Exception ex)
            {
                raw = null;
                RefreshQuickButtons();
                SetStatus($"The {label} rule couldn't be read: {ex.Message.TrimEnd('.')}. Nothing was changed.", error: true);
                return false;
            }
        }

        // Turning a blanket open on asks first; turning it off never does.
        private async void BtnQuickHTTPS_Click(object s, RoutedEventArgs e) => await QuickClick(async () =>
        {
            if (!QuickRead("HTTPS", "CUSTOM_HTTPS_Out", out var raw)) return;
            if (raw == null) { await QuickCreate("CUSTOM_HTTPS_Out", "HTTPS", 443); return; }
            if (!RuleText.IsOn(raw) && !ConfirmBlanketOpen("HTTPS", 443)) return;
            await QuickToggle("CUSTOM_HTTPS_Out", "HTTPS");
        });

        private async void BtnQuickHTTP_Click(object s, RoutedEventArgs e) => await QuickClick(async () =>
        {
            if (!QuickRead("HTTP", "CUSTOM_HTTP_Out", out var raw)) return;
            if (raw == null) { await QuickCreate("CUSTOM_HTTP_Out", "HTTP", 80); return; }
            if (!RuleText.IsOn(raw) && !ConfirmBlanketOpen("HTTP", 80)) return;
            await QuickToggle("CUSTOM_HTTP_Out", "HTTP");
        });

        // A quick switch click, while nothing else runs; an unforeseen error ends in the status line.
        private async System.Threading.Tasks.Task QuickClick(Func<System.Threading.Tasks.Task> click)
        {
            if (_busy) { SetStatus("Wait until the current task is done."); return; }
            try { await click(); }
            catch (Exception ex) { SetStatus($"Error: {ex.Message}", error: true); }
        }

        // The DNS rule (see DnsRule). A TCP DNS rule under this key, if there is one, is switched
        // along, so the switch never shows half of what it switches.
        private async void BtnQuickDNS_Click(object s, RoutedEventArgs e) => await QuickClick(async () =>
        {
            if (!QuickRead("DNS", DnsRule.UdpKey, out var raw)) return;
            if (raw == null) { await QuickCreate(DnsRule.UdpKey, "DNS", 53); return; }
            if (RuleText.IsOn(raw) && DnsOffIsUnsafe &&
                !HueConfirm.Ask(this, "Block DNS?",
                    "Blocks outbound name resolution. Windows 10 and Server 2019 cope; on builds 22000+ " +
                    "(Windows 11, Server 2025) parts of the system can stop working.",
                    "Turn DNS off", destructive: true))
                return;
            await QuickToggle(DnsRule.UdpKey, "DNS", DnsRule.TcpKey);
        });

        private bool ConfirmBlanketOpen(string label, int port) =>
            HueConfirm.Ask(this, $"Open blanket {label}?",
                $"This lets every program on this machine reach any server on TCP {port}. " +
                "It is meant for debugging only — turn it off again when you are done.",
                $"Open {label}", destructive: true);

        // A missing quick rule is created only after asking on or off: a click on an
        // undetermined button must not open anything by surprise.
        private async System.Threading.Tasks.Task QuickCreate(string ruleKey, string label, int port)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }

            var isDns = ruleKey == DnsRule.UdpKey;
            var what = isDns
                ? "It allows DNS (UDP 53) to one resolver, which you enter next, for the DNS Client " +
                  "service only: every program's lookups go through it, and a program that sends DNS itself is blocked." +
                  (DnsRule.ServiceDisabled()
                      ? "\n\nThe DNS Client service is set to Disabled here. This rule allows the DNS Client only, " +
                        "so while the service is off it allows nothing."
                      : "")
                : $"Switched on, it lets every program on this machine reach any server on TCP {port}. " +
                  "It is meant for debugging only.";
            var on = ThemedDialog.CreateOnOrOff(this, $"Create the {label} rule?",
                $"The {label} rule (CUSTOM {label} Out) doesn't exist. {what}\n\nCreate it switched off or on?",
                onIsRisky: !isDns);
            if (on == null) return;

            // Rule key → value.
            var values = new Dictionary<string, string>();
            if (isDns)
            {
                var gateway = LocalNet.Primary()?.Gateway ?? "";
                // Names what was put in the box, so the text stays true once it is overwritten and
                // the address can be typed back after a hasty change.
                var prefill = gateway.Length > 0 ? $"Prefilled with your gateway ({gateway}):" : "No gateway found to prefill.";
                var dlg = new InputDialog("DNS server", $"The resolver this machine may send DNS to (IPv4).\n{prefill}", gateway) { Owner = this };
                if (dlg.ShowDialog() != true) return;
                var server = dlg.Value.Trim();
                if (!LocalNet.IsAddress(server)) { SetStatus($"Not created: \"{server}\" is not an IPv4 address.", error: true); return; }
                values[DnsRule.UdpKey] = DnsRule.Value(17, server, on == true);
                // A TCP DNS rule under this key, if there is one, is switched along, so the switch
                // never shows half of what it switches.
                if (!QuickRead("DNS TCP", DnsRule.TcpKey, out var tcp)) return;
                if (tcp != null) values[DnsRule.TcpKey] = RuleText.WithActive(tcp, on == true);
            }
            else values[ruleKey] = $"v2.33|Action=Allow|Dir=Out|Protocol=6|RPort={port}|Active={(on == true ? "TRUE" : "FALSE")}|Name={RuleWriter.StoredName($"{label} Out")}|";

            // The TCP DNS rule kept along is a rule of yours rewritten.
            if (values.ContainsKey(DnsRule.TcpKey) &&
                !await RuleChangeAllowed(new RuleRemoval(new[] { DnsRule.TcpKey },
                    values.ToDictionary(v => v.Key, v => (string?)v.Value)))) return;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(QuickKeyPath, writable: true)
                                ?? Registry.LocalMachine.CreateSubKey(QuickKeyPath);
                if (key == null) { SetStatus("Cannot open registry.", error: true); return; }
                foreach (var (k, v) in values) key.SetValue(k, v, RegistryValueKind.String);
                var done = $"Created {(on == true ? "on" : "off")}: CUSTOM {label} Out" +
                           (values.ContainsKey(DnsRule.TcpKey) ? $" (kept {DnsRule.TcpName}, switched {(on == true ? "on" : "off")})" : "");
                LoadRules();
                RefreshQuickButtons();
                ApplyPolicy(done, values.Keys.ToArray());
            }
            catch (Exception ex) { SetStatus($"Error: {ex.Message}", error: true); }
        }

        // Partner rules follow the first rule's new state, so a pair can't end up half on.
        private async System.Threading.Tasks.Task QuickToggle(string ruleKey, string label, params string[] partners)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }

            // The new values first, so the session guard can judge them before anything is written.
            var newValues = new Dictionary<string, string?>();
            bool isActive;
            try
            {
                using var read = Registry.LocalMachine.OpenSubKey(QuickKeyPath, writable: false);
                if (read?.GetValue(ruleKey)?.ToString() is not { } existing) { RefreshQuickButtons(); return; }
                isActive = RuleText.IsOn(existing);
                foreach (var k in partners.Prepend(ruleKey))
                    if (read.GetValue(k)?.ToString() is { } value) newValues[k] = RuleText.WithActive(value, !isActive);
            }
            catch (Exception ex)
            {
                RefreshQuickButtons();
                SetStatus($"The {label} rule couldn't be read: {ex.Message.TrimEnd('.')}. Nothing was changed.", error: true);
                return;
            }
            if (!await RuleChangeAllowed(new RuleRemoval(newValues.Keys.ToList(), newValues))) return;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(QuickKeyPath, writable: true);
                if (key == null) { SetStatus("Cannot open registry.", error: true); return; }

                var written  = new List<string>();
                var names    = new List<string>();
                foreach (var (k, newVal) in newValues)
                {
                    key.SetValue(k, newVal!, RegistryValueKind.String);
                    written.Add(k);
                    names.Add(Shown(RuleWriter.Plain(newVal!.Split('|').FirstOrDefault(f => f.StartsWith("Name=", StringComparison.Ordinal))?[5..] ?? k)));
                }

                var done = $"{(isActive ? "Disabled" : "Enabled")}: {string.Join(" and ", names)}";
                LoadRules();
                RefreshQuickButtons();
                ApplyPolicy(done, written.ToArray());
            }
            catch (Exception ex) { SetStatus($"Error: {ex.Message}", error: true); }
        }

        private void RefreshQuickButtons()
        {
            // On is the risky side (red) for all three, on purpose. HTTPS and HTTP are blanket
            // opens. DNS is limited to one resolver and the DNS Client service, but it lets every
            // program's lookups out. The resolver doesn't keep them: to answer a name it can't
            // answer itself, it asks that domain's own name server, wherever that is. Whoever
            // owns a domain sees every lookup of a name under it, so data encoded in the names
            // looked up (DNS exfiltration, DNS tunnelling) reaches them through the one allowed
            // resolver. Red for DNS on is intended, not a mistake. (Turning DNS off on builds 22000+ asks
            // first; see BtnQuickDNS_Click.)
            RefreshQuickButton(BtnQuickHTTPS, "CUSTOM_HTTPS_Out",   "HTTPS", "Quick.Unsafe", "Quick.Safe");
            RefreshQuickButton(BtnQuickHTTP,  "CUSTOM_HTTP_Out",    "HTTP",  "Quick.Unsafe", "Quick.Safe");
            RefreshQuickButton(BtnQuickDNS,   DnsRule.UdpKey,       "DNS",   "Quick.Unsafe", "Quick.Safe");
        }

        private void RefreshQuickButton(Button btn, string ruleKey, string label, string onStyle, string offStyle)
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(QuickKeyPath, writable: false);
                var val = key?.GetValue(ruleKey)?.ToString();

                // "—" is no rule; "?" is kept for a rule that couldn't be read.
                if (val == null)
                {
                    btn.Styled("Hue.Button.Outline");
                    IconText.SetText(btn, $"{label} —");
                    btn.ToolTip = $"{ruleKey} — no rule; click to create it (asks on or off)";
                }
                else if (RuleText.IsOn(val))
                {
                    btn.Styled(onStyle);
                    IconText.SetText(btn, $"{label} ✓");
                    btn.ToolTip = $"{ruleKey} — enabled, click to disable";
                }
                else
                {
                    btn.Styled(offStyle);
                    IconText.SetText(btn, $"{label} ✗");
                    btn.ToolTip = $"{ruleKey} — disabled, click to enable";
                }
            }
            catch (Exception ex)
            {
                btn.Styled("Hue.Button.Outline");
                IconText.SetText(btn, $"{label} ?");
                btn.ToolTip = $"{ruleKey} — couldn't be read: {ex.Message}";
            }
        }

        private void RulesGrid_DoubleClick(object s, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (RulesGrid.SelectedItem is FirewallRule) OpenEditDialog();
        }

        // ── Edit / Add / Delete ───────────────────────────────────────────────

        private void BtnAddRule_Click   (object s, RoutedEventArgs e) => OpenAddDialog();
        private void BtnEditRule_Click  (object s, RoutedEventArgs e) => OpenEditDialog();
        private void BtnCopyRule_Click  (object s, RoutedEventArgs e) => OpenCopyDialog();
        private async void BtnDeleteRule_Click(object s, RoutedEventArgs e)
        {
            try { await DeleteSelected(); }
            catch (Exception ex) { SetStatus($"Delete error: {ex.Message}", error: true); }
        }

        // ── For the log viewer's "Allow…" ──────────────────────────────────────

        /// <summary>Reloads the rule list after a rule was saved from another window.</summary>
        public void RefreshRules() => LoadRules();

        /// <summary>
        /// An existing script rule the new allowance belongs in: same program (full path, with
        /// %SystemRoot% etc. expanded), same service, direction and protocol. Returns the rule
        /// to extend rather than creating a second one for the same program. Only rules the
        /// editor can change: GPO-Manual rules and rules with settings the editor doesn't write
        /// would open read-only, with nothing added.
        /// </summary>
        public FirewallRule? FindRuleToExtend(string programPath, string service, string direction, string protocol) =>
            SameProgramRules(programPath, service, direction, protocol).FirstOrDefault(r => !RuleEditWindow.OpensReadOnly(r));

        /// <summary>
        /// The rule FindRuleToExtend passed over because the editor can't change it, so the caller
        /// can say why a new rule was started; null when there is none, or an editable one was found.
        /// </summary>
        public FirewallRule? ReadOnlyMatch(string programPath, string service, string direction, string protocol) =>
            FindRuleToExtend(programPath, service, direction, protocol) != null
                ? null
                : SameProgramRules(programPath, service, direction, protocol).FirstOrDefault(RuleEditWindow.OpensReadOnly);

        private IEnumerable<FirewallRule> SameProgramRules(string programPath, string service, string direction, string protocol) =>
            _allRules.Where(r =>
                r.Source == "GPO-Script" && r.Action == "Allow" &&
                r.Direction == direction && r.Protocol == protocol &&
                string.Equals(r.Service ?? "", service ?? "", StringComparison.OrdinalIgnoreCase) &&
                r.Program.Length > 0 &&
                string.Equals(Environment.ExpandEnvironmentVariables(r.Program), programPath, StringComparison.OrdinalIgnoreCase));

        private void OpenEditDialog()
        {
            if (RefuseWhileBusy()) return;
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            RuleEditWindow.OpenEdit(rule, this);
            LoadRules();
        }

        private void OpenAddDialog()
        {
            if (RefuseWhileBusy()) return;
            RuleEditWindow.OpenNew(this);
            LoadRules();
        }

        private void OpenCopyDialog()
        {
            if (RefuseWhileBusy()) return;
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            RuleEditWindow.OpenCopy(rule, this);
            LoadRules();
        }

        private async System.Threading.Tasks.Task DeleteSelected()
        {
            if (RulesGrid.SelectedItem is not FirewallRule rule) return;
            if (rule.Source == "GPO-Manual") { SetStatus("GPO-Manual rules cannot be deleted here.", error: true); return; }
            if (rule.Source == "Local") { await DeleteLocal(rule); return; }

            if (!ThemedDialog.Confirm(this, "Confirm Delete",
                    $"Delete rule '{rule.NameDisplay}'?\n\nThis cannot be undone.",
                    "Delete", danger: true)) return;
            if (_busy) { SetStatus("Wait until the current task is done."); return; }
            if (!await RuleChangeAllowed(new RuleRemoval(new[] { rule.RegistryKey }))) return;

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(rule.RegistryPath, writable: true);
                key?.DeleteValue(rule.RegistryKey, false);

                LoadRules();
                SetStatus($"Deleted: {ShownName(rule)}");
                ApplyRuleChange(rule, $"Deleted: {ShownName(rule)}");
            }
            catch (Exception ex) { SetStatus($"Delete error: {ex.Message}", error: true); }
        }

        // One of Windows' local rules: the same path as Purge Local (backup, the firewall, the
        // registry as fallback, the live check), so it is gone at once where the firewall allows.
        private async System.Threading.Tasks.Task DeleteLocal(FirewallRule rule)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }
            if (_busy) { SetStatus("Wait until the current task is done."); return; }
            // Merge may have been switched since the button was last refreshed.
            if (MergeOnProfiles() is { Count: > 0 } mergeOn)
            {
                RefreshDeleteButton(rule);
                SetStatus(LocalDeleteNeedsMergeOff(mergeOn), error: true);
                return;
            }
            var name = rule.NameDisplay;
            if (!ThemedDialog.Confirm(this, "Delete local rule?", $"Delete {name}? A backup is saved first.", "Delete", danger: true))
                return;

            var id = rule.RegistryKey;
            SetBusy(true);
            SetStatus($"Deleting {name}…");
            LocalRules.SingleResult r;
            try
            {
                r = await Covered(() => Busy.RunAsync("Deleting a local rule", report =>
                {
                    report.Say($"{name}: saving a backup, then removing it through the firewall…");
                    return LocalRules.DeleteOne(id);
                }));
            }
            catch (Exception ex) { r = new LocalRules.SingleResult(ex.Message, null, false, false, LocalRules.FirewallAnswer.NotRun, "", null); }
            finally { SetBusy(false); }

            LoadRules();
            var (text, ok) = LocalDeleteText(name, r);
            SetStatus(text + (r.Backup != null ? $" Backup: {r.Backup}" : ""), error: !ok);
            // PowerShell's own words, wherever its answer wasn't a plain "removed".
            if (r.Answer == LocalRules.FirewallAnswer.Refused ||
                (r.Answer == LocalRules.FirewallAnswer.NotRun && (r.Problem == null || r.Message.Length > 0)))
                StatusText.ToolTip = r.Message.Length > 0 ? r.Message : "PowerShell gave no reason.";
        }

        // Only what is known: the firewall "refused" only when PowerShell returned an error, and
        // "in force until the next restart" only when the live check saw it still held.
        private static (string Text, bool Ok) LocalDeleteText(string name, LocalRules.SingleResult r)
        {
            if (r.Problem != null) return ($"Not deleted: {name}: {r.Problem}.", false);
            var held = r.StillHeld switch
            {
                true  => ", so it stays in force until the next restart",
                null  => "; whether the firewall still holds it couldn't be checked",
                false => "",
            };
            if (r.ByService)
                return r.Answer == LocalRules.FirewallAnswer.Removed
                    ? r.StillHeld switch
                      {
                          false => ($"Deleted {name}: removed from the firewall at once.", true),
                          true  => ($"Deleted {name}, but the firewall still holds it until the next restart.", false),
                          null  => ($"Deleted {name}: the firewall reported it removed{held}.", false),
                      }
                    : ($"Deleted {name}: the value is gone from the registry{held}.", r.StillHeld == false);
            return r.Answer switch
            {
                LocalRules.FirewallAnswer.Removed =>
                    ($"Deleted {name} from the registry: the firewall reported it removed, but the value was still there{held}.", r.StillHeld == false),
                LocalRules.FirewallAnswer.Refused => r.StillHeld == false
                    ? ($"Deleted {name} from the registry: the firewall refused to remove it, and doesn't hold it.", true)
                    : ($"Deleted {name} from the registry only: the firewall refused to remove it{held}.", false),
                _ => ($"Deleted {name} from the registry only: the removal through the firewall didn't run{held}.", false),
            };
        }

        // ── Purge Local (Windows auto-generated) rules ────────────────────────

        // With merge on, Windows' local rules count, and programs add them back as they install:
        // a purge would be undone without a word. Lock down's own removal comes after merge off.
        private void RefreshPurgeButton()
        {
            var count   = CountLocalRules();
            var mergeOn = MergeOnProfiles();
            IconText.SetText(BtnPurgeLocal, count > 0 ? $"Purge Local ({count})" : "Purge Local");
            BtnPurgeLocal.IsEnabled = _isAdmin && count > 0 && mergeOn.Count == 0 && !_busy;
            BtnPurgeLocal.ToolTip   = !_isAdmin
                ? "Administrator required"
                : mergeOn.Count > 0
                    ? PurgeNeedsMergeOff(mergeOn)
                    : count == 0
                        ? "No Local rules to purge"
                        : count == 1 ? "Back up and delete the one Windows-generated Local rule"
                        : $"Back up and delete all {count} Windows-generated Local rules";
        }

        private static string PurgeNeedsMergeOff(IEnumerable<string> mergeOn) =>
            $"Purge Local needs merge off on all three profiles. Merge is on for: {string.Join(", ", mergeOn)} (not configured counts as on).";

        /// <summary>
        /// The profiles where Windows' local rules count: merge on, or not set in policy (Windows
        /// then merges). A value that can't be read counts as on.
        /// </summary>
        private static List<string> MergeOnProfiles()
        {
            var on = new List<string>();
            foreach (var (label, key) in new[] { ("Domain", "DomainProfile"), ("Private", "PrivateProfile"), ("Public", "PublicProfile") })
            {
                try
                {
                    using var k = Registry.LocalMachine.OpenSubKey($@"{RegGPOProfiles}\{key}");
                    if (k?.GetValue("AllowLocalPolicyMerge") is int v && v == 0) continue;
                }
                catch { }
                on.Add(label);
            }
            return on;
        }

        // The merge banner and Purge Local follow the profiles' merge values.
        private void RefreshMergeState()
        {
            var mergeOn = MergeOnProfiles();
            MergeBanner.Visibility = mergeOn.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
            MergeBannerText.Text =
                $"Merge on for {string.Join(", ", mergeOn)} (not configured counts as on): Windows' local rules count there. " +
                "Programs add their own as they install, so what you leave blocked can be opened by a rule you never wrote.";
            RefreshPurgeButton();
            RefreshDeleteButton(RulesGrid.SelectedItem as FirewallRule);
        }

        private static int CountLocalRules() => LocalRules.Count();

        // "1 rule", "2 rules".
        private static string RulesWord(int n) => n == 1 ? "rule" : "rules";

        private static string LocalRemovalText(LocalRules.Removal r)
        {
            var parts = new List<string>();
            if (r.ByService > 0)  parts.Add($"{r.ByService} of Windows' local rules removed at once");
            if (r.ByRegistry > 0) parts.Add($"{r.ByRegistry} from the registry only (gone after the next restart)");
            if (r.NotRemoved.Count > 0) parts.Add($"{r.NotRemoved.Count} not removed");
            return parts.Count > 0 ? string.Join(", ", parts) : "No local rules to remove";
        }

        /// <summary>
        /// True, with the reason in the status line, while Lock down, Purge Local or another task
        /// runs: its first steps wait on background reads, and a rule editor or Setup opened
        /// meanwhile could write rules between its "before" snapshot and the policy it writes.
        /// </summary>
        public bool RefuseWhileBusy()
        {
            if (!_busy) return false;
            SetStatus("Wait until the current task is done.");
            return true;
        }

        private void SetBusy(bool busy)
        {
            _busy = busy;
            BtnLockdown.IsEnabled = !busy;
            RefreshPurgeButton();
        }

        // The overlay stops the mouse, not the keyboard: a button with focus still takes Space
        // and Enter. So for the whole run everything under it is switched off, and back on
        // however the run ends; the focus goes back where it was.
        private async System.Threading.Tasks.Task<T> Covered<T>(Func<System.Threading.Tasks.Task<T>> run)
        {
            LockContent(true);
            try { return await run(); }
            finally { LockContent(false); }
        }

        // Each lock remembers what it switched off and where the focus was; its unlock puts back
        // exactly that, so a part that was already off stays off.
        private readonly Stack<(List<UIElement> Under, UIElement? Focused)> _locks = new();

        private void LockContent(bool locked)
        {
            if (locked)
            {
                var focused = FocusManager.GetFocusedElement(this) as UIElement;
                var under   = Root.Children.OfType<UIElement>().Where(c => c != Busy && c.IsEnabled).ToList();
                foreach (var c in under) c.IsEnabled = false;
                _locks.Push((under, focused));
                return;
            }
            if (_locks.Count == 0) return;
            var (was, focus) = _locks.Pop();
            foreach (var c in was) c.IsEnabled = true;
            if (IsActive && focus is { IsEnabled: true, IsVisible: true }) focus.Focus();
        }

        // Through the firewall service, so the rules are gone from the running firewall at once
        // and the result can be checked, instead of lingering in memory until a restart.
        private async void BtnPurgeLocal_Click(object s, RoutedEventArgs e)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }

            // Lock down snapshots the local rules, so it must not run while they are half gone.
            if (_busy) return;
            // Merge may have been switched since the button was last refreshed.
            if (MergeOnProfiles() is { Count: > 0 } mergeOn)
            {
                RefreshMergeState();
                SetStatus(PurgeNeedsMergeOff(mergeOn), error: true);
                return;
            }
            SetBusy(true);
            _closeBlocker = "Purge Local";
            SetStatus("Purging local rules…");
            var count = CountLocalRules();
            LocalRules.PurgeResult r;
            try
            {
                r = await Covered(() => Busy.RunAsync("Purging local rules", report =>
                {
                    report.Say($"Saving a backup, then removing {count} {RulesWord(count)} through the firewall…");
                    return LocalRules.Purge();
                }));
            }
            catch (Exception ex) { r = new LocalRules.PurgeResult(0, 0, new List<string>(), ex.Message, null, null, null, null); }
            finally
            {
                _closeBlocker = null;
                SetBusy(false);
            }

            LoadRules();
            if (r.Problem != null)
            {
                SetStatus($"Purge Local: nothing removed, {r.Problem}.", error: true);
                return;
            }
            if (r.Backup == null) { SetStatus("No local rules to purge."); return; }
            var parts = new List<string>();
            if (r.ByService > 0)  parts.Add($"{r.ByService} local {RulesWord(r.ByService)} removed at once");
            if (r.ByRegistry > 0) parts.Add($"{r.ByRegistry} removed from the registry only, gone after the next restart");
            if (r.NotRemoved.Count > 0) parts.Add($"{r.NotRemoved.Count} not removed");
            var held = r.StillHeld switch
            {
                null  => "the running firewall couldn't be asked what it still holds",
                0     => "the running firewall holds none of them",
                var n => $"the running firewall still holds {n} of them",
            };
            var saved = r.Wfw != null
                ? $"  Backup → {r.Backup} (and {System.IO.Path.GetFileName(r.Wfw)}, which puts them back at once)"
                : $"  Backup → {r.Backup} (no firewall export: {r.WfwProblem}; putting back waits for a restart)";
            SetStatus($"Purge Local: {string.Join("; ", parts)}; {held}." + saved,
                      error: r.NotRemoved.Count > 0 || r.StillHeld is null or > 0);
            if (r.NotRemoved.Count > 0) StatusText.ToolTip = string.Join("\n", r.NotRemoved.Take(30));
        }

        // ── DNS Client (Dnscache) status + scheduled disable ──────────────────

        private const string RegDnscache = @"SYSTEM\CurrentControlSet\Services\Dnscache";

        // Service start type: 2=Automatic, 3=Manual, 4=Disabled
        private static int GetDnscacheStart()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(RegDnscache, writable: false);
                return k?.GetValue("Start") is int v ? v : -1;
            }
            catch { return -1; }
        }

        // Live run state via `sc query`, to avoid an extra package dependency.
        private static bool IsDnscacheRunning()
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo
                {
                    FileName = WindowsTools.PathOf(WindowsTools.Tool.Sc), Arguments = "query Dnscache",
                    CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true
                });
                var output = p?.StandardOutput.ReadToEnd() ?? "";
                p?.WaitForExit();
                return output.Contains("RUNNING");
            }
            catch { return false; }
        }

        // For the DNS warnings: Windows 11 is 22000 and up.
        private static int GetWindowsBuild()
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", writable: false);
                var s = k?.GetValue("CurrentBuildNumber")?.ToString() ?? "0";
                return int.TryParse(s, out var b) ? b : 0;
            }
            catch { return 0; }
        }

        private void RefreshDnsClientButton()
        {
            var start   = GetDnscacheStart();
            if (WindowsTools.NotFound(WindowsTools.Tool.Sc, "the service's running state can't be read") is { } missing)
            {
                SetDnsClientState("Brush.Stale", "Unknown");
                BtnDnsClient.ToolTip   = $"{missing}. Start={StartLabel(start)}.";
                BtnDnsClient.IsEnabled = _isAdmin && start != -1;
                return;
            }
            var running = IsDnscacheRunning();

            // Start=Disabled but still running: the change waits for a reboot or a manual stop.
            if (start == 4 && running)
            {
                SetDnsClientState("Brush.Warn", "Disable pending");
                BtnDnsClient.ToolTip     = "Start=Disabled, but service still running. Reboot or manually stop to take effect. Click to re-enable.";
            }
            else if (start == 4)
            {
                SetDnsClientState("Brush.Error", "Disabled");
                BtnDnsClient.ToolTip     = "DNS Client disabled and stopped. Click to re-enable (Start=Automatic).";
            }
            else if (running)
            {
                SetDnsClientState("Brush.Ok", "Running");
                BtnDnsClient.ToolTip     = $"Dnscache running (Start={StartLabel(start)}). Click to schedule disable.";
            }
            else
            {
                SetDnsClientState("Brush.Stale", "Stopped");
                BtnDnsClient.ToolTip     = $"Dnscache stopped (Start={StartLabel(start)}). Click to schedule disable.";
            }

            BtnDnsClient.IsEnabled = _isAdmin && start != -1;
        }

        private static string StartLabel(int start) => start switch
        {
            2 => "Automatic", 3 => "Manual", 4 => "Disabled", _ => "?"
        };

        private void BtnDnsClient_Click(object s, RoutedEventArgs e)
        {
            if (!_isAdmin) { SetStatus("Administrator required.", error: true); return; }

            var start = GetDnscacheStart();
            if (start == -1) { SetStatus("Cannot read Dnscache service key.", error: true); return; }

            if (start == 4)
            {
                if (!ThemedDialog.Confirm(this, "Re-enable DNS Client",
                        "Re-enable DNS Client?\n\nSets Dnscache Start = 2 (Automatic).\nTakes effect after reboot (or start the service manually).",
                        "Re-enable at reboot")) return;
                SetDnscacheStart(2, "re-enabled (Automatic)");
                return;
            }

            // Windows 10 resolves in each program once the service is off. Windows 11 did too until
            // an update changed it; which one isn't known, so the measured build is named, not a boundary.
            var build = GetWindowsBuild();
            var win11 = build >= 22000;
            var warn  = win11
                ? "\n\n⚠ Measured on build 26300.9457: with the DNS Client disabled, Windows resolves no names. " +
                  "Programs that ask it get an error at once and send nothing. Only programs with their own DNS " +
                  "code still send DNS. Earlier Windows 11 builds resolved in each program instead, until an " +
                  "update changed that; which update isn't known."
                : "";

            if (!QuickRead("DNS", DnsRule.UdpKey, out var dnsRule)) return;
            var msg = "Disable DNS Client (Dnscache) at the next reboot?\n\n" +
                      $"Current Start = {StartLabel(start)} ({start})  →  Disabled (4)\n\n" +
                      "This is a registry write only. It does NOT stop the running service — " +
                      "the change takes effect on reboot, or when you stop the process manually.\n\n" +
                      "Current Start value is backed up first." +
                      (dnsRule != null && dnsRule.Contains("Svc=Dnscache", StringComparison.OrdinalIgnoreCase)
                          ? "\n\nThe DNS rules allow the DNS Client service only, so DNS a program sends itself is blocked too."
                          : "") + warn;

            if (!ThemedDialog.Confirm(this, "Disable DNS Client", msg,
                    "Disable at reboot", danger: win11)) return;

            string backupPath;
            try { backupPath = WriteDnscacheBackup(start); }
            catch (Exception ex) { SetStatus($"Not changed: the backup could not be written ({ex.Message}).", error: true); return; }
            SetDnscacheStart(4, $"scheduled disable — reboot or stop the process to apply.  Backup → {backupPath}");
        }

        private void SetDnscacheStart(int value, string statusVerb)
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(RegDnscache, writable: true);
                if (k == null) { SetStatus("Cannot open Dnscache key for writing.", error: true); return; }
                k.SetValue("Start", value, RegistryValueKind.DWord);
                RefreshDnsClientButton();
                SetStatus($"DNS Client {statusVerb}");
            }
            catch (Exception ex) { SetStatus($"DNS Client error: {ex.Message}", error: true); }
        }

        // The prior Start value as a mergeable .reg in the app folder (double-click to restore).
        private static string WriteDnscacheBackup(int currentStart) =>
            AppFolder.WriteReg("dnscache-start",
                $"[HKEY_LOCAL_MACHINE\\{RegDnscache}]\r\n\"Start\"=dword:{currentStart:x8}\r\n");

        // ── Helpers ──────────────────────────────────────────────────────────

        // Status dot (Hue.Marker in a fixed status colour) plus the word, never colour alone.
        private void SetDnsClientState(string markerBrushKey, string word)
        {
            var dot = new ContentControl { VerticalAlignment = VerticalAlignment.Center }
                .Styled("Hue.Marker")
                .Ref(ForegroundProperty, markerBrushKey);
            var row = new StackPanel { Orientation = Orientation.Horizontal };
            row.Children.Add(dot);
            row.Children.Add(new TextBlock { Text = word, Margin = new Thickness(7, 0, 0, 0), VerticalAlignment = VerticalAlignment.Center });
            BtnDnsClient.Content = row;
            AutomationProperties.SetName(BtnDnsClient, "DNS Client: " + word);
        }

        // ── Making written policy take effect ────────────────────────────────
        //  Every write is followed by gpupdate (computer, waited for) and a check of what the
        //  firewall applies (PolicyApply). The status line reports the outcome, including for
        //  writes made in the rule editor or from the log window.

        private void WirePolicyApply()
        {
            PolicyApply.Started   += OnPolicyStarted;
            PolicyApply.Completed += OnPolicyCompleted;
            Closed += (_, _) =>
            {
                PolicyApply.Started   -= OnPolicyStarted;
                PolicyApply.Completed -= OnPolicyCompleted;
            };
            // Something the start-up questions changed (moved values, the Group Policy setting).
            Loaded += (_, _) =>
            {
                if (PolicyApply.PendingAtStart is { } what)
                {
                    PolicyApply.PendingAtStart = null;
                    ApplyPolicy(what);
                }
            };
        }

        private void ApplyPolicy(string what, params string[] rules) => _ = PolicyApply.RunAsync(what, rules);

        // A rule write: policy rules get applied and checked; Windows' own local rules are
        // reported as not checked (gpupdate and the check cover policy only).
        private void ApplyRuleChange(FirewallRule rule, string what, bool definitionChanged = false)
        {
            if (rule.Source == "Local") PolicyApply.ReportLocal(what);
            else if (definitionChanged) ApplyPolicy(what, rule.RegistryKey);
            else ApplyPolicy(what);
        }

        private void OnPolicyStarted(string what) => Dispatcher.InvokeAsync(() =>
            SetStatus($"{what} — applying (gpupdate)…", Tone.Applying));

        // While Lock down runs, its result line is its own, written once the whole run is done:
        // the policy can be in force while Windows' local rules are still being removed.
        private bool _holdPolicyResult;

        private void OnPolicyCompleted(PolicyApply.Result r) => Dispatcher.InvokeAsync(() =>
        {
            if (_holdPolicyResult) return;
            SetStatus(r.Summary, r.IsProblem ? Tone.Error : r.InForce ? Tone.InForce : Tone.Normal);
            StatusText.ToolTip = r.Detail;         // after SetStatus, which clears it
        });

        // The status line's tone, chosen where the message is made, never read from its text:
        // applying = amber text, a change in force = green text, problems = red as before.
        private enum Tone { Normal, Applying, InForce, Error }

        private void SetStatus(string msg, bool error = false) => SetStatus(msg, error ? Tone.Error : Tone.Normal);

        private void SetStatus(string msg, Tone tone)
        {
            StatusText.Text       = msg;
            StatusText.ToolTip    = null;          // a previous result's details don't belong to this message
            // Normal messages inherit the status bar's text colour and background; errors use the
            // error text token on a pale error tint, which stays until the next message.
            switch (tone)
            {
                case Tone.Error:   StatusText.Ref(TextBlock.ForegroundProperty, "Brush.ErrorText"); break;
                case Tone.Applying: StatusText.Ref(TextBlock.ForegroundProperty, "Brush.WarnText"); break;
                case Tone.InForce: StatusText.Ref(TextBlock.ForegroundProperty, "Brush.OkText");   break;
                default:           StatusText.ClearValue(TextBlock.ForegroundProperty);             break;
            }
            if (tone == Tone.Error) StatusBarFrame.Ref(Border.BackgroundProperty, "Brush.ErrorSoft");
            else                    StatusBarFrame.ClearValue(Border.BackgroundProperty);
        }

        // A guard's Kept or PutBack line: not an error means the policy check found it in force.
        private static Tone GuardTone(MergeOffOutcome o) => o.Error ? Tone.Error : Tone.InForce;

        // A name from another writer in a message: hidden characters shown, as in the list.
        private static string Shown(string text) => TextHygiene.Reveal(text).Shown;

        // A rule's name in a status line, as the list shows it: the app's own without CUSTOM.
        private static string ShownName(FirewallRule rule) =>
            Shown(rule.Source == "GPO-Script" ? RuleWriter.Plain(rule.Name) : rule.Name);

        private static bool IsRunningAsAdmin()
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }
}
