using Microsoft.Extensions.Configuration;

namespace Activout.Extensions.Configuration.Kdbx.Tests;

internal static class TestData
{
    public static string PathOf(string name) => Path.Combine(AppContext.BaseDirectory, "TestFiles", name);

    public static IConfigurationRoot Load(string name, Action<KdbxConfigurationOptions> configure) =>
        new ConfigurationBuilder().AddKdbxFile(PathOf(name), configure).Build();

    public static Dictionary<string, string?> Flatten(IConfiguration configuration) =>
        configuration.AsEnumerable().Where(kv => kv.Value != null).ToDictionary(kv => kv.Key, kv => kv.Value);
}
