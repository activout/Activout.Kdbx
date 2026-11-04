using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using static Activout.Extensions.Configuration.Kdbx.Tests.TestData;

namespace Activout.Extensions.Configuration.Kdbx.Tests;

public sealed class ReloadTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("kdbx-reload-").FullName;
    private string DbPath => Path.Combine(_dir, "secrets.kdbx");

    private ConfigurationRoot? _config;

    public void Dispose()
    {
        _config?.Dispose(); // stops the file watcher before the directory is deleted
        Directory.Delete(_dir, recursive: true);
    }

    private IConfigurationRoot Build(Action<FileLoadExceptionContext>? onLoadException = null)
    {
        File.Copy(PathOf("mapping.kdbx"), DbPath);
        _config = (ConfigurationRoot)new ConfigurationBuilder()
            .AddKdbxFile(source =>
            {
                source.Path = DbPath;
                source.ReloadOnChange = true;
                source.OnLoadException = onLoadException;
                source.ResolveFileProvider();
                source.Options.Password = "mapping-pw";
            })
            .Build();
        return _config;
    }

    private static async Task ReplaceAndWaitForReload(IConfiguration config, string path, byte[] content)
    {
        var reloaded = new TaskCompletionSource();
        using var _ = ChangeToken.OnChange(config.GetReloadToken, () => reloaded.TrySetResult());
        await File.WriteAllBytesAsync(path, content);
        await reloaded.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task ReplacedFile_IsReloaded()
    {
        var config = Build();
        Assert.Equal("top-secret", config["TopLevel"]);

        await ReplaceAndWaitForReload(config, DbPath, File.ReadAllBytes(PathOf("mapping-v2.kdbx")));

        Assert.Equal("changed-secret", config["TopLevel"]);
    }

    [Fact]
    public async Task BrokenFile_OnReload_KeepsPreviousData_AndReportsError()
    {
        var errors = new List<Exception>();
        var config = Build(ctx => errors.Add(ctx.Exception));

        var halfWritten = File.ReadAllBytes(PathOf("mapping-v2.kdbx"))[..1000];
        await ReplaceAndWaitForReload(config, DbPath, halfWritten);

        Assert.Equal("top-secret", config["TopLevel"]);
        Assert.IsType<InvalidDataException>(Assert.Single(errors));
    }
}
