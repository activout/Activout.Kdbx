// Run with: KDBX_PASSWORD=mapping-pw dotnet run -- --Kdbx:Path="$(realpath ../../tests/Activout.Extensions.Configuration.Kdbx.Tests/TestFiles/mapping.kdbx)"
var builder = WebApplication.CreateBuilder(args);

builder.Configuration.AddKdbxFile(
    builder.Configuration["Kdbx:Path"] ?? "secrets.kdbx",
    optional: true,
    reloadOnChange: true,
    options => options.PasswordProvider = () => Environment.GetEnvironmentVariable("KDBX_PASSWORD"));

var app = builder.Build();

// Never return secrets from a real endpoint; this only shows whether the key was found.
app.MapGet("/", (IConfiguration config) => config["Database:Main"] is null
    ? "Database:Main is not set"
    : "Database:Main is set");

app.Run();
