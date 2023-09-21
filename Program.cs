using DNSmonitor.Services;
// using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

#region cors
/*
builder.Services.AddCors(options =>
{
    options.AddPolicy(
            name: "Cors",
            build =>
            {
                build.WithOrigins("*", "*", "*")
                .AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod();
            }
        );
});
*/
#endregion

#region Serilog
/*
#region Serilog
builder.Host.UseSerilog((context, logger) =>
{
    logger.ReadFrom.Configuration(context.Configuration);
    logger.Enrich.FromLogContext();
});
#endregion
*/
#endregion

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

// app.UseCors("Cors");

MonitorService.CapturePacket();
Console.ReadKey();
MonitorService.StopCapture();

app.Run();
