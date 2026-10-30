using System.Windows;
using System.Windows.Media;

namespace FirewallManager
{
    /// <summary>
    /// Theme tokens from code. HueTheme rule: never build a brush from a colour; point the
    /// property at the resource so it follows the theme (and a Windows contrast theme) live.
    /// </summary>
    internal static class ThemeRefs
    {
        /// <summary>Points <paramref name="property"/> at a theme resource; returns the element for chaining.</summary>
        public static T Ref<T>(this T element, DependencyProperty property, string key) where T : FrameworkElement
        {
            element.SetResourceReference(property, key);
            return element;
        }

        /// <summary>Applies a keyed theme style (e.g. "Hue.Tag") to an element built in code.</summary>
        public static T Styled<T>(this T element, string styleKey) where T : FrameworkElement
        {
            element.SetResourceReference(FrameworkElement.StyleProperty, styleKey);
            return element;
        }

        /// <summary>
        /// The current brush for a token, for values that must live on a data object (a row's
        /// colour in a bound list). Looked up when the row is built, so rows pick up theme
        /// changes the next time the list refreshes.
        /// </summary>
        public static Brush Brush(string key) => (Brush)Application.Current.FindResource(key);
    }
}
