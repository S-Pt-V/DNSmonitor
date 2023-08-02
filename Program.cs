
using DNSmonitor;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

#region cors
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
#endregion

/*
#region Serilog
builder.Host.UseSerilog((context, logger) =>
{
    logger.ReadFrom.Configuration(context.Configuration);
    logger.Enrich.FromLogContext();
});
#endregion
*/

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

app.UseCors("Cors");

MonitorService.StratListen();

app.Run();
