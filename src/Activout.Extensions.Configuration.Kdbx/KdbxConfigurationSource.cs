using Microsoft.Extensions.Configuration;

namespace Activout.Extensions.Configuration.Kdbx;

/// <summary>
/// A KDBX file as an <see cref="IConfigurationSource"/>.
/// </summary>
public sealed class KdbxConfigurationSource : FileConfigurationSource
{
    /// <summary>How the database is opened and mapped.</summary>
    public KdbxConfigurationOptions Options { get; set; } = new();

    /// <inheritdoc/>
    public override IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        KdbxConfigurationMapper.Validate(Options);
        EnsureDefaults(builder);
        return new KdbxConfigurationProvider(this);
    }
}

/// <summary>
/// Loads configuration from a KDBX file.
/// </summary>
/// <remarks>
/// If a reload fails, for example because the file is half-written, the previous data is kept and the
/// error is passed to <see cref="FileConfigurationSource.OnLoadException"/>, if set.
/// </remarks>
/// <param name="source">The source settings.</param>
public sealed class KdbxConfigurationProvider(KdbxConfigurationSource source) : FileConfigurationProvider(source)
{
    private bool _loaded;

    /// <inheritdoc/>
    public override void Load(Stream stream)
    {
        try
        {
            Data = KdbxConfigurationMapper.Load(stream, source.Options);
            _loaded = true;
        }
        catch (Exception ex) when (_loaded)
        {
            // The base class would clear Data and rethrow on a background thread.
            source.OnLoadException?.Invoke(new FileLoadExceptionContext { Provider = this, Exception = ex });
        }
    }
}

/// <summary>
/// A KDBX stream as an <see cref="IConfigurationSource"/>.
/// </summary>
public sealed class KdbxStreamConfigurationSource : StreamConfigurationSource
{
    /// <summary>How the database is opened and mapped.</summary>
    public KdbxConfigurationOptions Options { get; set; } = new();

    /// <inheritdoc/>
    public override IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        KdbxConfigurationMapper.Validate(Options);
        return new KdbxStreamConfigurationProvider(this);
    }
}

/// <summary>
/// Loads configuration from a KDBX stream.
/// </summary>
/// <param name="source">The source settings.</param>
public sealed class KdbxStreamConfigurationProvider(KdbxStreamConfigurationSource source) : StreamConfigurationProvider(source)
{
    /// <inheritdoc/>
    public override void Load(Stream stream) => Data = KdbxConfigurationMapper.Load(stream, source.Options);
}
