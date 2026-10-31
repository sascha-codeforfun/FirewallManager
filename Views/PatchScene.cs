using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using HueThemeKit;

namespace FirewallManager
{
    // ─────────────────────────────────────────────────────────────────────────
    //  The patch reminder in the header: plasters (and, long overdue, stitches) on the
    //  Windows name while this machine is behind on cumulative updates (PatchAge), and,
    //  on a wide window, Flick: the flame from the app's icon, who comes out of a door,
    //  patches the name up, and — on Windows 10 past its end of support — shakes its
    //  head, flares up red and holds up how many days it has been, then trudges back.
    //  The further behind, the wearier: slower steps, heavy lids, a sigh; long overdue,
    //  a plaster slips and has to be picked up; a year past end of support, a yawn.
    //
    //  Ctrl+click on the logo shows a level picker next to the status pills: the plasters of
    //  any level, and the scene on request, for machines that are never behind.
    //
    //  Artwork: vector shapes, so sharp at any scaling. Its colours are the drawing's
    //  own (the logo's cyan, plaster beige), like app_256.png; the door and the stitches
    //  use the theme's tokens. Nothing here blocks or changes anything.
    // ─────────────────────────────────────────────────────────────────────────

    internal static class Art
    {
        public static Color C(string hex) => (Color)ColorConverter.ConvertFromString(hex);
        public static SolidColorBrush B(string hex) { var b = new SolidColorBrush(C(hex)); b.Freeze(); return b; }
        public static Geometry G(string data) { var g = Geometry.Parse(data); g.Freeze(); return g; }

        /// <summary>Path data for an ellipse (two arcs).</summary>
        public static string Ell(double cx, double cy, double rx, double ry) =>
            FormattableString.Invariant($"M{cx - rx},{cy} A{rx},{ry} 0 1 0 {cx + rx},{cy} A{rx},{ry} 0 1 0 {cx - rx},{cy} Z ");

        public static T At<T>(T e, double x, double y) where T : UIElement
        {
            Canvas.SetLeft(e, x);
            Canvas.SetTop(e, y);
            return e;
        }
    }

    // ── a plaster ──────────────────────────────────────────────────────────────

    internal static class Plaster
    {
        /// <summary>A plaster w × h (its centre at 0,0 once placed with its own offset), rotated, scalable from its centre.</summary>
        public static Canvas Make(double w, double h, double rotation, bool contrast)
        {
            var fill  = contrast ? SystemColors.WindowBrush     : Art.B("#E8C49A");
            var edge  = contrast ? SystemColors.WindowTextBrush : Art.B("#C99D6E");
            var pad   = contrast ? SystemColors.WindowBrush     : Art.B("#F3DCC0");
            var dot   = contrast ? SystemColors.WindowTextBrush : Art.B("#B98E62");
            var c = new Canvas { Width = w, Height = h, IsHitTestVisible = false };
            var u = h / 7;   // details drawn for a 7-high plaster, scaled to this one
            c.Children.Add(new Rectangle { Width = w, Height = h, RadiusX = h / 2, RadiusY = h / 2, Fill = fill, Stroke = edge, StrokeThickness = 0.6 * u });
            var pw = w * 0.34;
            c.Children.Add(Art.At(new Rectangle { Width = pw, Height = h - 1.6 * u, RadiusX = 0.8 * u, RadiusY = 0.8 * u, Fill = pad }, (w - pw) / 2, 0.8 * u));
            var d = 0.9 * u;
            for (var row = 0; row < 2; row++)
                for (var col = 0; col < 3; col++)
                    c.Children.Add(Art.At(new Ellipse { Width = d, Height = d, Fill = dot },
                        (w - pw) / 2 + pw * (0.2 + 0.3 * col) - d / 2, h * (0.32 + 0.36 * row) - d / 2));
            c.RenderTransformOrigin = new Point(0.5, 0.5);
            c.RenderTransform = new TransformGroup { Children = { new ScaleTransform(1, 1), new RotateTransform(rotation) } };
            return c;
        }

        public static ScaleTransform Scale(Canvas plaster) => (ScaleTransform)((TransformGroup)plaster.RenderTransform).Children[0];
    }

    // ── Flick ──────────────────────────────────────────────────────────────────

    internal enum FlickPose { Idle, Walk1, Walk2, Think, Patch, Shake, Sign, Nod, Stoop, Yawn, Flare }

    /// <summary>The mascot, drawn in a 40 × 60 box with its feet on y = 56. Scaled by its container.</summary>
    internal sealed class Flick : Canvas
    {
        private static readonly Brush Teal = Art.B("#0E7490"), Cyan = Art.B("#22D3EE"), Ink = Art.B("#0B1220"),
                                      White = Brushes.White, Pink = Art.B("#F472B6"), Tear = Art.B("#7DD3FC");

        private readonly Path _legs = new() { Stroke = Teal, StrokeThickness = 2.8, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
        private readonly Path _feet = new() { Fill = Teal };
        private readonly Path _arms = new() { Stroke = Teal, StrokeThickness = 2.8, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
        private readonly Path _hands = new() { Fill = Cyan, Stroke = Teal, StrokeThickness = 0.6 };
        private readonly Canvas _head = new();
        private readonly TranslateTransform[] _pupils = { new(), new() };
        private readonly Path _lids = new() { Fill = Cyan, Stroke = Teal, StrokeThickness = 0.7 };
        private readonly Path _brows = new() { Stroke = Teal, StrokeThickness = 0.9, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
        private readonly Path _mouthLine = new() { Stroke = Ink, StrokeThickness = 1.2, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
        private readonly Path _mouthFill = new() { Fill = Ink };
        private readonly Path _tongue = new() { Fill = Pink };
        private readonly Path _cheeks = new() { Fill = Pink, Opacity = 0.45 };
        private readonly Path _tear = new() { Fill = Tear, Data = Art.G("M28.6,30.2 Q29.6,32.1 28.6,32.9 Q27.6,32.1 28.6,30.2 Z") };
        private readonly Canvas _held, _heldBox;
        private readonly Path _flame;
        private readonly TextBlock _signDays = new() { FontWeight = FontWeights.ExtraBold, FontSize = 22, Foreground = Art.B("#B91C1C"), TextAlignment = TextAlignment.Center, Width = SignW };
        private const double SignW = 120, SignH = 44;

        /// <summary>The centre of the plaster held up in the patch pose, in Flick's box.</summary>
        public const double HeldX = 21, HeldY = 15.5;

        public RotateTransform HeadTurn { get; } = new(0, 20, 44);

        /// <summary>The flame on the head: its colours (white core to the edge), and a scale from its base.</summary>
        public GradientStop[] FlameStops { get; }
        public ScaleTransform FlameScale { get; } = new(1, 1, 21, 26);
        public UIElement Flame => _flame;

        /// <summary>The held plaster can fall: a drop from the hands, and a spin about its centre.</summary>
        public TranslateTransform HeldFall { get; } = new();
        public RotateTransform HeldSpin { get; } = new(0, HeldX, HeldY);

        /// <summary>A breath of air from the mouth (a sigh), and smoke from the flame's tip.</summary>
        public Canvas SighPuff { get; } = Puff(27.5, 37.5, 0.8, "#94A3B8");
        public Canvas Smoke { get; } = Puff(16, 0.5, 1.25, "#64748B");   // above the flared flame's tip

        /// <summary>The scene's level (0–3): heavier lids and a flatter mouth the further behind.</summary>
        public int Weariness { get; set; }
        public Canvas Sign { get; } = new() { Width = SignW, Height = SignH };

        public Flick()
        {
            Width = 40; Height = 60;
            Children.Add(new Path { Fill = Brushes.Black, Opacity = 0.4, Data = Art.G(Art.Ell(20, 56.5, 9.5, 1.6)) });
            Children.Add(_legs); Children.Add(_feet); Children.Add(_arms); Children.Add(_hands);

            var body = new RadialGradientBrush { Center = new Point(0.4, 0.3), GradientOrigin = new Point(0.4, 0.3), RadiusX = 0.8, RadiusY = 0.8,
                GradientStops = { new GradientStop(Art.C("#A5F3FC"), 0), new GradientStop(Art.C("#22D3EE"), 0.55), new GradientStop(Art.C("#0891B2"), 1) } };
            var flame = new RadialGradientBrush { Center = new Point(0.5, 0.75), GradientOrigin = new Point(0.5, 0.75), RadiusX = 0.8, RadiusY = 0.8,
                GradientStops = { new GradientStop(Colors.White, 0), new GradientStop(Art.C("#CFFAFE"), 0.35), new GradientStop(Art.C("#22D3EE"), 0.8), new GradientStop(Art.C("#0891B2"), 1) } };
            _head.RenderTransform = HeadTurn;
            _head.Children.Add(new Path { Fill = body, Data = Art.G(Art.Ell(20, 33.5, 12, 11.6)) });
            FlameStops = flame.GradientStops.ToArray();
            _flame = new Path { Fill = flame, RenderTransform = FlameScale,
                Data = Art.G("M13.5,25 C12.2,18 17.8,16.2 16.6,9.5 C20.8,12.4 24.6,15 24,21.6 C25.8,20.4 26.6,18.6 26.8,16.4 C30.4,21.2 28.6,25.4 26.6,26.6 Z") };
            _head.Children.Add(_flame);
            for (var i = 0; i < 2; i++)
            {
                var cx = i == 0 ? 15.3 : 24.7;
                _head.Children.Add(new Path { Fill = White, Data = Art.G(Art.Ell(cx, 31.5, 3.3, 3.8)) });
                var eye = new Canvas { RenderTransform = _pupils[i] };
                eye.Children.Add(new Path { Fill = Ink, Data = Art.G(Art.Ell(cx, 31.8, 2.0, 2.0)) });
                eye.Children.Add(new Path { Fill = White, Data = Art.G(Art.Ell(cx + 0.8, 30.9, 0.75, 0.75)) });
                _head.Children.Add(eye);
            }
            foreach (var part in new UIElement[] { _lids, _brows, _cheeks, _mouthFill, _tongue, _mouthLine, _tear })
                _head.Children.Add(part);
            Children.Add(_head);

            _held = Plaster.Make(18, 6.3, -12, contrast: false);
            _heldBox = new Canvas { RenderTransform = new TransformGroup { Children = { HeldSpin, HeldFall } } };
            _heldBox.Children.Add(Art.At(_held, HeldX - 9, HeldY - 3.15));
            Children.Add(_heldBox);
            Children.Add(SighPuff);
            Children.Add(Smoke);

            // The sign, held out to the left at head height by its right edge (the header has no room
            // above the head): "381 days" over "since end of support".
            Sign.Children.Add(new Rectangle { Width = SignW, Height = SignH, RadiusX = 4, RadiusY = 4, Fill = Art.B("#F8FAFC"), Stroke = Art.B("#CBD5E1"), StrokeThickness = 1 });
            Sign.Children.Add(Art.At(_signDays, 0, 3));
            Sign.Children.Add(Art.At(new TextBlock { Text = "since end of support", FontWeight = FontWeights.SemiBold, FontSize = 11,
                Foreground = Art.B("#334155"), TextAlignment = TextAlignment.Center, Width = SignW }, 0, 29));
            Sign.RenderTransformOrigin = new Point(1, 0.5);
            Sign.RenderTransform = new ScaleTransform(0, 0);
            Children.Add(Art.At(Sign, -3 - SignW, 30 - SignH / 2));

            Pose(FlickPose.Idle);
        }

        public string SignDays { set => _signDays.Text = value; }

        // A small cloud of three overlapping puffs (nonzero fill, so no holes where they overlap).
        private static Canvas Puff(double x, double y, double s, string colour)
        {
            var c = new Canvas { Opacity = 0, IsHitTestVisible = false, RenderTransform = new TranslateTransform() };
            c.Children.Add(new Path { Fill = Art.B(colour), Data = Art.G("F1 " +
                Art.Ell(x, y, 2.2 * s, 1.8 * s) + Art.Ell(x + 2.4 * s, y - 1.2 * s, 1.8 * s, 1.5 * s) + Art.Ell(x + 0.9 * s, y - 2.7 * s, 1.5 * s, 1.3 * s)) });
            return c;
        }

        public void Look(double dx, double dy)
        {
            foreach (var p in _pupils) { p.X = dx; p.Y = dy; }
        }

        /// <param name="sad">Keeps the shaking-head face (walking back on Windows 10).</param>
        public void Pose(FlickPose pose, bool sad = false)
        {
            _legs.Data = Art.G(pose switch
            {
                FlickPose.Walk1 => "M17,44 L13.5,54 M23,44 L26,53",
                FlickPose.Walk2 => "M17,44 L18.5,54 M23,44 L21.5,54",
                _               => "M16.5,44 L15.5,54 M23.5,44 L24.5,54",
            });
            _feet.Data = Art.G(pose switch
            {
                FlickPose.Walk1 => Art.Ell(12.8, 55, 2.6, 1.4) + Art.Ell(27, 54.5, 2.6, 1.4),
                FlickPose.Walk2 => Art.Ell(18.4, 55.2, 2.6, 1.4) + Art.Ell(22.2, 55.2, 2.6, 1.4),
                _               => Art.Ell(14.8, 55.2, 2.6, 1.4) + Art.Ell(25.2, 55.2, 2.6, 1.4),
            });
            var (arms, l, r) = pose switch
            {
                FlickPose.Walk1 => ("M9,35 L6,39.5 M31,35 L35,40.5", (5.6, 40.0), (35.4, 41.0)),
                FlickPose.Walk2 => ("M9,35 L5,40.5 M31,35 L34,39.5", (4.6, 41.0), (34.4, 40.0)),
                FlickPose.Patch => ("M9,34 L15,20 M31,34 L27,19", (15.2, 19.6), (27.0, 18.6)),
                FlickPose.Think => ("M9,35 L5.5,41 M31,35 L26,39.8", (5.2, 41.5), (24.8, 40.4)),
                FlickPose.Shake => ("M9,36 L6.5,43 M31,36 L33.5,43", (6.3, 43.5), (33.7, 43.5)),
                FlickPose.Sign  => ("M9,34 L-1.5,30.5 M31,35 L34.5,41", (-1.8, 30.4), (34.8, 41.5)),
                FlickPose.Stoop => ("M9,36 L17,49.5 M31,36 L25,49.5", (17.0, 50.0), (25.0, 50.0)),
                FlickPose.Yawn  => ("M9,34 L4,24 M31,34 L36,24", (3.8, 23.4), (36.2, 23.4)),
                FlickPose.Flare => ("M9,35 L3.5,38 M31,35 L36.5,38", (3.2, 38.2), (36.8, 38.2)),
                _               => ("M9,35 L5.5,41 M31,35 L34.5,41", (5.2, 41.5), (34.8, 41.5)),
            };
            _arms.Data  = Art.G(arms);
            _hands.Data = Art.G(Art.Ell(l.Item1, l.Item2, 1.9, 1.9) + Art.Ell(r.Item1, r.Item2, 1.9, 1.9));

            var (lids, brows, mouth, cheeks, tear) = (sad ? FlickPose.Shake : pose) switch
            {
                FlickPose.Patch => (0.0, "focus", "tongue", true, false),
                FlickPose.Think => (Weariness >= 3 ? 0.3 : 0.0, "up", "o", true, false),
                FlickPose.Shake => (0.45, "worried", "flat", false, false),
                FlickPose.Sign  => (0.25, "worried", "flat", false, true),
                FlickPose.Nod   => (0.4, "none", "grin", true, false),
                FlickPose.Stoop => (0.2, "worried", "o", false, false),
                FlickPose.Yawn  => (0.75, "none", "yawn", false, false),
                FlickPose.Flare => (0.0, "alarm", "o", false, false),
                _ when Weariness >= 3 => (0.38, "none", "flat", false, false),
                _ when Weariness == 2 => (0.2, "up", "smile", true, false),
                _               => (0.0, "up", "smile", true, false),
            };
            _lids.Data = lids > 0 ? Art.G(Lids(lids)) : null;
            _brows.Data = brows switch
            {
                "up"      => Art.G("M13,25 Q15.3,23.6 17.6,24.8 M22.4,24.8 Q24.7,23.6 27,25"),
                "worried" => Art.G("M13,25.4 Q15.6,24.9 17.6,23.4 M22.4,23.4 Q24.4,24.9 27,25.4"),
                "focus"   => Art.G("M13,24.2 Q15.4,24.2 17.6,25.2 M22.4,25.2 Q24.6,24.2 27,24.2"),
                "alarm"   => Art.G("M12.8,24 Q15.3,21.6 17.8,23.2 M22.2,23.2 Q24.7,21.6 27.2,24"),
                _         => null,
            };
            _mouthLine.Data = mouth switch
            {
                "smile"  => Art.G("M17.2,38 Q20,41 22.8,38"),
                "tongue" => Art.G("M17.5,38.2 Q20,39.6 22.5,38.2"),
                "flat"   => Art.G("M17.6,38.8 Q20,38.2 22.4,38.8"),
                _        => null,
            };
            _mouthFill.Data = mouth switch
            {
                "grin" => Art.G("M16.8,37.6 Q20,42.2 23.2,37.6 Z"),
                "o"    => Art.G(Art.Ell(20, 38.8, 1.3, 1.6)),
                "yawn" => Art.G(Art.Ell(20, 39.4, 2.5, 3.1)),
                _      => null,
            };
            _tongue.Data = mouth switch
            {
                "grin"   => Art.G("M18.2,39.6 Q20,41 21.8,39.6 Z"),
                "yawn"   => Art.G("M18.2,41.4 Q20,40 21.8,41.4 Q20,42.6 18.2,41.4 Z"),
                "tongue" => Art.G("M21,38.9 Q22.6,39.1 22.6,40.5 Q21.2,40.9 20.7,39.6 Z"),
                _        => null,
            };
            _cheeks.Data = cheeks ? Art.G(Art.Ell(12.6, 36, 2, 1.2) + Art.Ell(27.4, 36, 2, 1.2)) : null;
            _tear.Visibility = tear ? Visibility.Visible : Visibility.Collapsed;
            _heldBox.Visibility = pose is FlickPose.Patch or FlickPose.Stoop ? Visibility.Visible : Visibility.Collapsed;
        }

        private static string Lids(double amount)
        {
            var s = "";
            foreach (var cx in new[] { 15.3, 24.7 })
            {
                var top = 31.5 - 3.8;
                var edge = top + 2 * 3.8 * amount;
                s += FormattableString.Invariant(
                    $"M{cx - 3.8},{top - 0.6} L{cx + 3.8},{top - 0.6} L{cx + 3.8},{edge - 0.6} Q{cx},{edge + 1.4} {cx - 3.8},{edge - 0.6} Z ");
            }
            return s;
        }
    }

    // ── the stage ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Plasters on the Windows name, and the scene. The plasters live in a layer over the name
    /// (shown whenever the machine is behind); the scene plays on a stage over the whole header.
    /// </summary>
    internal sealed class PatchScene
    {
        private const double Scale = 1.0;            // Flick about 57 units tall
        private const double Speed = 95;             // walking, units per second, when one update behind
        private const double Stride = 0.16;          // seconds per step, likewise

        // This run's gait: slower the further behind.
        private double _speed = Speed, _stride = Stride, _bob = 1.5;
        private bool _trudge;

        /// <summary>The free width left of the Windows block the scene needs: the door, and the sign beside Flick.</summary>
        public const double Room = 170;

        private readonly Canvas _stage, _layer;
        private readonly FrameworkElement _title, _ground;
        private readonly List<Canvas> _plasters = new();
        private readonly List<double> _plasterX = new();   // centres, as fractions of the name's width
        private Path? _stitches;
        private PatchAge.State? _state;

        /// <param name="ground">Its bottom edge is the floor Flick walks on.</param>
        public PatchScene(Canvas stage, Canvas plasterLayer, FrameworkElement title, FrameworkElement ground)
        {
            _stage = stage; _layer = plasterLayer; _title = title; _ground = ground;
            _title.SizeChanged += (_, _) => Lay();
        }

        public PatchAge.State? State
        {
            get => _state;
            set { _state = value; Lay(); }
        }

        public bool Running { get; private set; }

        private CancellationTokenSource? _cts;

        /// <summary>Ends a running scene at once; the plasters stay as they belong.</summary>
        public void Stop() => _cts?.Cancel();

        // ── plasters ─────────────────────────────────────────────────────────

        /// <summary>Puts the plasters (and stitches) for the current level on the name.</summary>
        public void Lay()
        {
            Stop();
            _layer.Children.Clear();
            _plasters.Clear();
            _plasterX.Clear();
            _stitches = null;
            var level = _state?.Level ?? 0;
            if (level == 0 || _title.ActualWidth <= 0) return;

            var w = _title.ActualWidth;
            var h = _title.ActualHeight;
            var contrast = HueContrast.IsActive;
            if (level >= 3)
            {
                // Stitches across the name: a seam with cross stitches.
                var seam = $"M{F(w * 0.03)},{F(h * 0.55)} L{F(w * 0.97)},{F(h * 0.57)} ";
                for (var x = w * 0.07; x < w * 0.95; x += 11)
                    seam += $"M{F(x - 3)},{F(h * 0.55 - 5.5)} L{F(x + 3)},{F(h * 0.55 + 6)} ";
                _stitches = new Path { Data = Art.G(seam), StrokeThickness = 1.7, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round };
                _stitches.SetResourceReference(Shape.StrokeProperty, "Brush.ErrorText");
                _layer.Children.Add(_stitches);
            }
            var spots = level == 1
                ? new[] { (0.24, -20.0, 30.0, 10.5) }
                : new[] { (0.24, -20.0, 30.0, 10.5), (0.64, 16.0, 27.0, 9.6), (0.92, -8.0, 25.5, 9.0) };
            foreach (var (fx, rot, pw, ph) in spots)
            {
                var p = Plaster.Make(pw, ph, rot, contrast);
                Art.At(p, w * fx - pw / 2, h * 0.5 - ph / 2);
                _layer.Children.Add(p);
                _plasters.Add(p);
                _plasterX.Add(fx);
            }
        }

        private static string F(double v) => v.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture);

        // ── the scene ────────────────────────────────────────────────────────

        /// <summary>
        /// Plays the scene from a door at doorX (stage units, its left edge). Stop() ends it at once
        /// and leaves the plasters as they belong.
        /// </summary>
        public async Task PlayAsync(double doorX)
        {
            if (Running || _state is not { Behind: true } state || _plasters.Count == 0) return;
            Running = true;
            _cts = new CancellationTokenSource();
            var cancel = _cts.Token;
            var door = new Door();
            var flick = new Flick { Weariness = state.Level };
            var pace = state.Level >= 3 ? 0.72 : state.Level == 2 ? 0.88 : 1.0;
            _speed = Speed * pace; _stride = Stride / pace;
            _bob = state.Level >= 3 ? 0.8 : 1.5;
            _trudge = state.Level >= 3;
            flick.Pose(FlickPose.Idle);
            var holder = new Canvas { Width = 40 * Scale, Height = 60 * Scale };
            var bob = new TranslateTransform();
            flick.RenderTransform = new TransformGroup { Children = { new ScaleTransform(Scale, Scale), bob } };
            holder.Children.Add(flick);
            var facing = new ScaleTransform(1, 1, 20 * Scale, 0);
            holder.RenderTransform = facing;
            holder.Opacity = 0;

            try
            {
                var ground = _ground.TranslatePoint(new Point(0, _ground.ActualHeight), _stage).Y - 3;
                var titleOrigin = _title.TranslatePoint(new Point(0, 0), _stage);
                var spots = _plasterX.ConvertAll(fx => titleOrigin.X + _title.ActualWidth * fx);
                // This run's plasters: a Lay() while a finished step's continuation is still queued
                // replaces _plasters (empty if the name has no width then) before the next await throws.
                var plasters = _plasters.ToArray();
                // The held plaster (centre 21,15.5 in Flick's box) has to reach the middle of the name:
                // a hop up by whatever the arms don't reach.
                var reach = Math.Max(0, (ground - (56.5 - Flick.HeldY) * Scale) - (titleOrigin.Y + _title.ActualHeight * 0.5));
                var doorCentre = doorX + Door.DoorWidth * 0.5;

                foreach (var p in _plasters) Plaster.Scale(p).ScaleX = Plaster.Scale(p).ScaleY = 0;
                if (_stitches != null) _stitches.Opacity = 0;

                _stage.Children.Add(Art.At(door, doorX, ground - Door.DoorHeight));
                _stage.Children.Add(holder);
                void Place(double centreX) => Art.At(holder, centreX - 20 * Scale, ground - 56.5 * Scale);
                Place(doorCentre);

                // The door draws itself in and opens; Flick steps out and looks around.
                await Fade(door, 1, 0.5, cancel);
                await door.OpenAsync(cancel);
                await Fade(holder, 1, 0.3, cancel);
                flick.Look(-0.9, 0); await Wait(0.45, cancel);
                flick.Look(0.9, 0);  await Wait(0.45, cancel);
                flick.Look(0, 0);    await Wait(0.2, cancel);

                // To each plaster: look up, reach up, press it on.
                var x = doorCentre;
                for (var i = 0; i < spots.Count; i++)
                {
                    x = await WalkAsync(flick, holder, facing, bob, x, spots[i] - (Flick.HeldX - 20) * Scale, Place, cancel);
                    flick.Pose(FlickPose.Think); flick.Look(0.4, -1.0);
                    await Wait(0.35, cancel);
                    flick.Pose(FlickPose.Patch); flick.Look(0.6, -1.2);
                    // Long overdue, tired hands: the middle plaster slips and has to be picked up.
                    if (state.Level >= 3 && i == 1) await DropAndPickUpAsync(flick, cancel);
                    await Animate(bob, TranslateTransform.YProperty, -reach, 0.22, cancel, overshoot: true);
                    await Wait(0.2, cancel);
                    await Grow(Plaster.Scale(plasters[i]), 0.25, cancel);
                    flick.Pose(FlickPose.Idle); flick.Look(0, 0);
                    await Animate(bob, TranslateTransform.YProperty, 0, 0.2, cancel);
                    bob.BeginAnimation(TranslateTransform.YProperty, null); bob.Y = 0;
                    await Wait(0.25, cancel);
                }
                if (_stitches != null)
                {
                    flick.Pose(FlickPose.Patch); flick.Look(0.6, -1.2);
                    await Animate(bob, TranslateTransform.YProperty, -reach, 0.22, cancel, overshoot: true);
                    await Fade(_stitches, 1, 0.6, cancel);
                    flick.Pose(FlickPose.Idle); flick.Look(0, 0);
                    await Animate(bob, TranslateTransform.YProperty, 0, 0.2, cancel);
                    bob.BeginAnimation(TranslateTransform.YProperty, null); bob.Y = 0;
                }

                // Two or more behind: a sigh at the work done.
                if (state.Level >= 2) await SighAsync(flick, cancel);

                // Back off to just left of the name, to look at the work (and, on Windows 10, so the
                // sign held out to the left goes over the free header, not over the name).
                x = await WalkAsync(flick, holder, facing, bob, x, titleOrigin.X - 24 * Scale, Place, cancel);
                facing.ScaleX = 1;
                flick.Pose(FlickPose.Think); flick.Look(0.5, -1.0);
                await Wait(0.9, cancel);

                if (state.DaysSinceEndOfSupport is { } days)
                {
                    // A year and more past its end of support: a yawn first.
                    if (days > 365) await YawnAsync(flick, cancel);
                    // Windows 10 past its end of support: a slow head shake, a red flare at the number,
                    // then the sign, held a good while with the flame burnt low.
                    flick.Pose(FlickPose.Shake); flick.Look(0, 0.6);
                    await ShakeAsync(flick.HeadTurn, 9, 4, 1.6, cancel);
                    await FlareAsync(flick, cancel);
                    flick.SignDays = $"{days} days";
                    flick.Pose(FlickPose.Sign);
                    await Grow((ScaleTransform)flick.Sign.RenderTransform, 0.3, cancel);
                    await Wait(8, cancel);
                    await Shrink((ScaleTransform)flick.Sign.RenderTransform, 0.25, cancel);
                    flick.Pose(FlickPose.Shake);
                    // Back to the door, still shaking its head; the flame slowly finds its cyan again.
                    var cool = CoolAsync(flick, Math.Abs(doorCentre - x) / _speed, cancel);
                    x = await WalkAsync(flick, holder, facing, bob, x, doorCentre, Place, cancel, shakeHead: true);
                    await cool;
                }
                else
                {
                    flick.Pose(FlickPose.Shake); flick.Look(0, 0.6);
                    await ShakeAsync(flick.HeadTurn, 6, 2, 0.8, cancel);
                    flick.Pose(FlickPose.Nod);
                    await Wait(0.5, cancel);
                    x = await WalkAsync(flick, holder, facing, bob, x, doorCentre, Place, cancel);
                }

                // Through the door, which closes and fades.
                await Fade(holder, 0, 0.3, cancel);
                await door.CloseAsync(cancel);
                await Fade(door, 0, 0.5, cancel);
            }
            catch (OperationCanceledException) { }
            finally
            {
                _stage.Children.Remove(door);
                _stage.Children.Remove(holder);
                foreach (var p in _plasters)
                {
                    var s = Plaster.Scale(p);
                    s.BeginAnimation(ScaleTransform.ScaleXProperty, null);
                    s.BeginAnimation(ScaleTransform.ScaleYProperty, null);
                    s.ScaleX = s.ScaleY = 1;
                }
                if (_stitches != null) { _stitches.BeginAnimation(UIElement.OpacityProperty, null); _stitches.Opacity = 1; }
                _cts?.Dispose();
                _cts = null;
                Running = false;
            }
        }

        // Walks from x to target: legs alternate, a little bob, facing the way it goes.
        private async Task<double> WalkAsync(Flick flick, Canvas holder, ScaleTransform facing, TranslateTransform bob,
                                                    double from, double to, Action<double> place, CancellationToken cancel,
                                                    bool shakeHead = false)
        {
            if (Math.Abs(to - from) < 0.5) return from;
            facing.ScaleX = to < from ? -1 : 1;
            var seconds = Math.Abs(to - from) / _speed;
            var started = DateTime.UtcNow;
            var step = -1;
            while (true)
            {
                cancel.ThrowIfCancellationRequested();
                var t = Math.Min(1, (DateTime.UtcNow - started).TotalSeconds / seconds);
                place(from + (to - from) * t);
                var phase = (int)((DateTime.UtcNow - started).TotalSeconds / _stride);
                if (phase != step)
                {
                    step = phase;
                    flick.Pose(phase % 2 == 0 ? FlickPose.Walk1 : FlickPose.Walk2, sad: shakeHead);
                    if (shakeHead) flick.Look(0, 0.6);
                    else if (_trudge) flick.Look(0.6, 0.8);   // eyes on the floor
                    bob.Y = phase % 2 == 0 ? 0 : -_bob;
                }
                if (shakeHead) flick.HeadTurn.Angle = 7 * Math.Sin((DateTime.UtcNow - started).TotalSeconds * 7);
                if (t >= 1) break;
                await Task.Delay(16, cancel);
            }
            bob.Y = 0;
            flick.HeadTurn.Angle = 0;
            flick.Pose(shakeHead ? FlickPose.Shake : FlickPose.Idle);
            if (_trudge && !shakeHead) flick.Look(0, 0);
            return to;
        }

        // ── the weary and the cross bits ─────────────────────────────────────

        // The red of the flare, and the low ember it burns down to while the sign is up;
        // in the order of the flame's stops (core to edge). Cyan is the flame's own.
        private static readonly Color[] Red   = { Art.C("#FFF7ED"), Art.C("#FDE047"), Art.C("#EF4444"), Art.C("#991B1B") };
        private static readonly Color[] Ember = { Art.C("#FED7AA"), Art.C("#FB923C"), Art.C("#C2410C"), Art.C("#7C2D12") };
        private static readonly Color[] Cyan  = { Colors.White,     Art.C("#CFFAFE"), Art.C("#22D3EE"), Art.C("#0891B2") };

        // The held plaster slips, falls spinning to the floor; a look down, a stoop, and it's back in hand.
        private static async Task DropAndPickUpAsync(Flick flick, CancellationToken cancel)
        {
            await Wait(0.25, cancel);
            var floor = 56.5 - 2.5 - Flick.HeldY;                        // its centre just above the feet line
            await Task.WhenAll(
                Run(flick.HeldFall, TranslateTransform.YProperty, new DoubleAnimation(floor, TimeSpan.FromSeconds(0.38))
                    { FillBehavior = FillBehavior.HoldEnd, EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseIn } }, cancel),
                Animate(flick.HeldSpin, RotateTransform.AngleProperty, 35, 0.38, cancel));
            flick.Pose(FlickPose.Stoop); flick.Look(0.2, 1.4);           // "oh."
            await Wait(0.45, cancel);
            await Animate(flick.HeadTurn, RotateTransform.AngleProperty, 9, 0.3, cancel);
            await Wait(0.3, cancel);
            await Task.WhenAll(
                Animate(flick.HeldFall, TranslateTransform.YProperty, 0, 0.35, cancel),
                Animate(flick.HeldSpin, RotateTransform.AngleProperty, 0, 0.35, cancel),
                Animate(flick.HeadTurn, RotateTransform.AngleProperty, 0, 0.35, cancel));
            Settle(flick.HeldFall, TranslateTransform.YProperty, 0);
            Settle(flick.HeldSpin, RotateTransform.AngleProperty, 0);
            Settle(flick.HeadTurn, RotateTransform.AngleProperty, 0);
            flick.Pose(FlickPose.Patch); flick.Look(0.6, -1.2);
            await Wait(0.2, cancel);
        }

        // Arms down, lids down, a breath of air drifts off.
        private static async Task SighAsync(Flick flick, CancellationToken cancel)
        {
            flick.Pose(FlickPose.Shake); flick.Look(0, 0.6);
            await PuffAsync(flick.SighPuff, 7, -5, 0.9, cancel);
            await Wait(0.2, cancel);
            flick.Pose(FlickPose.Idle); flick.Look(0, 0);
        }

        // Arms up, head back, mouth wide.
        private static async Task YawnAsync(Flick flick, CancellationToken cancel)
        {
            flick.Pose(FlickPose.Yawn); flick.Look(0, -0.5);
            await Animate(flick.HeadTurn, RotateTransform.AngleProperty, -7, 0.5, cancel);
            await Wait(0.9, cancel);
            await Animate(flick.HeadTurn, RotateTransform.AngleProperty, 0, 0.4, cancel);
            Settle(flick.HeadTurn, RotateTransform.AngleProperty, 0);
            flick.Pose(FlickPose.Idle); flick.Look(0, 0);
            await Wait(0.3, cancel);
        }

        // Eyes wide; the flame shoots up red and flickers for about a second, a puff of smoke,
        // then it burns down small and dim.
        private static async Task FlareAsync(Flick flick, CancellationToken cancel)
        {
            flick.Pose(FlickPose.Flare); flick.Look(0, -0.4);
            var s = flick.FlameScale;
            await Task.WhenAll(
                Recolour(flick, Red, 0.18, cancel),
                Animate(s, ScaleTransform.ScaleXProperty, 1.2, 0.25, cancel, overshoot: true),
                Animate(s, ScaleTransform.ScaleYProperty, 1.5, 0.25, cancel, overshoot: true));
            Settle(s, ScaleTransform.ScaleXProperty, 1.2);
            Settle(s, ScaleTransform.ScaleYProperty, 1.5);
            var started = DateTime.UtcNow;
            Task? smoke = null;
            while (true)
            {
                cancel.ThrowIfCancellationRequested();
                var t = (DateTime.UtcNow - started).TotalSeconds;
                if (t >= 0.8) break;
                if (smoke == null && t >= 0.45) smoke = PuffAsync(flick.Smoke, 3, -16, 1.3, cancel);
                s.ScaleY = 1.5 + 0.09 * Math.Sin(t * 41);
                s.ScaleX = 1.2 + 0.05 * Math.Sin(t * 33 + 1);
                await Task.Delay(16, cancel);
            }
            flick.Pose(FlickPose.Shake); flick.Look(0, 0.6);
            await Task.WhenAll(
                Recolour(flick, Ember, 0.6, cancel),
                Animate(s, ScaleTransform.ScaleXProperty, 0.85, 0.6, cancel),
                Animate(s, ScaleTransform.ScaleYProperty, 0.78, 0.6, cancel),
                Fade(flick.Flame, 0.75, 0.6, cancel));
            if (smoke != null) await smoke;
        }

        // Back to its own cyan and size over the given time.
        private static Task CoolAsync(Flick flick, double seconds, CancellationToken cancel)
        {
            seconds = Math.Max(1.5, seconds);
            return Task.WhenAll(
                Recolour(flick, Cyan, seconds, cancel),
                Animate(flick.FlameScale, ScaleTransform.ScaleXProperty, 1, seconds, cancel),
                Animate(flick.FlameScale, ScaleTransform.ScaleYProperty, 1, seconds, cancel),
                Fade(flick.Flame, 1, seconds, cancel));
        }

        private static Task Recolour(Flick flick, Color[] to, double seconds, CancellationToken cancel) =>
            Task.WhenAll(flick.FlameStops.Select((stop, i) =>
                Run(stop, GradientStop.ColorProperty, new ColorAnimation(to[i], TimeSpan.FromSeconds(seconds)) { FillBehavior = FillBehavior.HoldEnd }, cancel)));

        // A puff shows, drifts by (dx, dy) and fades on the way.
        private static async Task PuffAsync(Canvas puff, double dx, double dy, double seconds, CancellationToken cancel)
        {
            var move = (TranslateTransform)puff.RenderTransform;
            Settle(move, TranslateTransform.XProperty, 0);
            Settle(move, TranslateTransform.YProperty, 0);
            Settle(puff, UIElement.OpacityProperty, 0);
            await Fade(puff, 0.85, 0.15, cancel);
            await Task.WhenAll(
                Animate(move, TranslateTransform.XProperty, dx, seconds, cancel),
                Animate(move, TranslateTransform.YProperty, dy, seconds, cancel),
                Fade(puff, 0, seconds, cancel));
        }

        // Drops a held animation and sets the plain value (a held animation outranks a set value).
        private static void Settle(IAnimatable target, DependencyProperty property, double value)
        {
            target.BeginAnimation(property, null);
            ((DependencyObject)target).SetValue(property, value);
        }

        private static async Task ShakeAsync(RotateTransform head, double degrees, int times, double seconds, CancellationToken cancel)
        {
            var started = DateTime.UtcNow;
            while (true)
            {
                cancel.ThrowIfCancellationRequested();
                var t = (DateTime.UtcNow - started).TotalSeconds / seconds;
                if (t >= 1) break;
                head.Angle = degrees * Math.Sin(t * times * 2 * Math.PI) * (1 - t * 0.3);
                await Task.Delay(16, cancel);
            }
            head.Angle = 0;
        }

        private static Task Wait(double seconds, CancellationToken cancel) => Task.Delay(TimeSpan.FromSeconds(seconds), cancel);

        internal static Task Fade(UIElement element, double to, double seconds, CancellationToken cancel) =>
            Animate(element, UIElement.OpacityProperty, to, seconds, cancel);

        private static async Task Grow(ScaleTransform scale, double seconds, CancellationToken cancel)
        {
            var a = Animate(scale, ScaleTransform.ScaleXProperty, 1, seconds, cancel, overshoot: true);
            var b = Animate(scale, ScaleTransform.ScaleYProperty, 1, seconds, cancel, overshoot: true);
            await Task.WhenAll(a, b);
        }

        private static async Task Shrink(ScaleTransform scale, double seconds, CancellationToken cancel)
        {
            var a = Animate(scale, ScaleTransform.ScaleXProperty, 0, seconds, cancel);
            var b = Animate(scale, ScaleTransform.ScaleYProperty, 0, seconds, cancel);
            await Task.WhenAll(a, b);
        }

        /// <summary>A from-current animation that finishes as a task; cancelling stops it where it is.</summary>
        internal static Task Animate(IAnimatable target, DependencyProperty property, double to, double seconds,
                                     CancellationToken cancel, bool overshoot = false) =>
            Run(target, property, new DoubleAnimation(to, TimeSpan.FromSeconds(seconds))
            {
                FillBehavior = FillBehavior.HoldEnd,
                EasingFunction = overshoot ? new BackEase { EasingMode = EasingMode.EaseOut, Amplitude = 0.5 }
                                           : new SineEase { EasingMode = EasingMode.EaseInOut },
            }, cancel);

        private static Task Run(IAnimatable target, DependencyProperty property, AnimationTimeline animation, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();
            var done = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            animation.Completed += (_, _) => done.TrySetResult(true);
            var registration = cancel.Register(() =>
            {
                target.BeginAnimation(property, null);
                done.TrySetCanceled(cancel);
            });
            _ = done.Task.ContinueWith(_ => registration.Dispose(), TaskScheduler.Default);
            target.BeginAnimation(property, animation);
            return done.Task;
        }
    }

    // ── the door ───────────────────────────────────────────────────────────────

    /// <summary>A door in the theme's line colours; opening lets a wedge of accent light out onto the floor.</summary>
    internal sealed class Door : Canvas
    {
        public const double DoorWidth = 34, DoorHeight = 56;
        private readonly Rectangle _light, _panel;
        private readonly Ellipse _knob;
        private readonly Path _spill;
        private readonly ScaleTransform _swing = new(1, 1, 0, 0);

        public Door()
        {
            Width = DoorWidth; Height = DoorHeight;
            Opacity = 0;
            IsHitTestVisible = false;
            var accent = (Application.Current?.TryFindResource("Brush.AccentText") as SolidColorBrush)?.Color ?? Colors.Cyan;

            _spill = new Path
            {
                Data = Art.G(FormattableString.Invariant($"M{DoorWidth},{DoorHeight} L0,{DoorHeight} L-14,{DoorHeight + 3} L{DoorWidth + 30},{DoorHeight + 3} Z")),
                Fill = new LinearGradientBrush(Color.FromArgb(140, accent.R, accent.G, accent.B), Color.FromArgb(0, accent.R, accent.G, accent.B), 90),
                Opacity = 0,
            };
            Children.Add(_spill);
            _light = new Rectangle { Width = DoorWidth, Height = DoorHeight, RadiusX = 2, RadiusY = 2, Opacity = 0,
                Fill = new LinearGradientBrush(Color.FromRgb(0xCF, 0xFA, 0xFE), accent, 90) };
            Children.Add(_light);
            var frame = new Rectangle { Width = DoorWidth, Height = DoorHeight, RadiusX = 2, RadiusY = 2, StrokeThickness = 2 };
            frame.SetResourceReference(Shape.StrokeProperty, "Brush.TextDim");
            Children.Add(frame);
            _panel = new Rectangle { Width = DoorWidth, Height = DoorHeight, RadiusX = 2, RadiusY = 2, StrokeThickness = 1.5, RenderTransform = _swing };
            _panel.SetResourceReference(Shape.FillProperty, "Brush.Raised");
            _panel.SetResourceReference(Shape.StrokeProperty, "Brush.TextDim");
            Children.Add(_panel);
            var knob = new Ellipse { Width = 3.6, Height = 3.6 };
            knob.SetResourceReference(Shape.FillProperty, "Brush.TextDim");
            Children.Add(Art.At(knob, DoorWidth - 8, DoorHeight * 0.52));
            _knob = knob;
        }

        public async Task OpenAsync(CancellationToken cancel)
        {
            _knob.Visibility = Visibility.Collapsed;
            await Task.WhenAll(
                PatchScene.Animate(_swing, ScaleTransform.ScaleXProperty, 0.28, 0.5, cancel),
                PatchScene.Fade(_light, 0.85, 0.5, cancel),
                PatchScene.Fade(_spill, 1, 0.6, cancel));
        }

        public async Task CloseAsync(CancellationToken cancel)
        {
            await Task.WhenAll(
                PatchScene.Animate(_swing, ScaleTransform.ScaleXProperty, 1, 0.4, cancel),
                PatchScene.Fade(_light, 0, 0.4, cancel),
                PatchScene.Fade(_spill, 0, 0.4, cancel));
            _knob.Visibility = Visibility.Visible;
        }
    }
}
