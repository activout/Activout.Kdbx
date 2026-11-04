using Activout.Extensions.Configuration.Kdbx;

// Extension methods live in this namespace by convention.
// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.Configuration;

/// <summary>
/// Extension methods for adding KDBX databases to an <see cref="IConfigurationBuilder"/>.
/// </summary>
public static class KdbxConfigurationExtensions
{
    /// <summary>Adds a required KDBX file, without reloading.</summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="path">Path relative to the builder's base path.</param>
    /// <param name="configure">Sets the master key and mapping options.</param>
    public static IConfigurationBuilder AddKdbxFile(this IConfigurationBuilder builder, string path,
        Action<KdbxConfigurationOptions> configure) =>
        builder.AddKdbxFile(path, optional: false, reloadOnChange: false, configure);

    /// <summary>Adds a KDBX file.</summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="path">Path relative to the builder's base path.</param>
    /// <param name="optional">Whether a missing file is allowed.</param>
    /// <param name="reloadOnChange">Whether to reload when the file changes. Every load runs the KDF.</param>
    /// <param name="configure">Sets the master key and mapping options.</param>
    public static IConfigurationBuilder AddKdbxFile(this IConfigurationBuilder builder, string path, bool optional,
        bool reloadOnChange, Action<KdbxConfigurationOptions> configure)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(configure);
        return builder.AddKdbxFile(source =>
        {
            source.Path = path;
            source.Optional = optional;
            source.ReloadOnChange = reloadOnChange;
            source.ResolveFileProvider();
            configure(source.Options);
        });
    }

    /// <summary>Adds a KDBX file, configured through the source.</summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="configureSource">Configures the source.</param>
    public static IConfigurationBuilder AddKdbxFile(this IConfigurationBuilder builder,
        Action<KdbxConfigurationSource> configureSource) =>
        builder.Add(configureSource);

    /// <summary>Adds a KDBX database read from a stream.</summary>
    /// <param name="builder">The configuration builder.</param>
    /// <param name="stream">The database.</param>
    /// <param name="configure">Sets the master key and mapping options.</param>
    public static IConfigurationBuilder AddKdbxStream(this IConfigurationBuilder builder, Stream stream,
        Action<KdbxConfigurationOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        return builder.Add<KdbxStreamConfigurationSource>(source =>
        {
            source.Stream = stream;
            configure(source.Options);
        });
    }
}
