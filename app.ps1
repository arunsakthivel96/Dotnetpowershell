param (
    [string]$name,
    [string]$path= (Get-Location).Path,
    [string]$folder = ""
)
try {

# Mandatory parameters validation
$apiName = $name

if($apiName -eq $null -or $apiName -eq "") {
    do {
        write-host "[x] API name is mandatory either Provide the API Name or use [Ctrl + C] to exit and run the script with .\MedisysWebAPIGenerator.ps1 -name <Web.API.Name>" -ForegroundColor Red
        $apiName = Read-Host "Enter the API name"
    } until ($apiName -ne "")

}
$apiName = $apiName -replace " ", ""
$apiPath = $path
$currentDir = (Get-Location).Path
$apiRootFolder = $folder

$isRename = $false
if($folder -ne $null -or $folder -ne "") {
	$isRename = $true
}
if($folder -eq $null -or $folder -eq "") {
    $apiRootFolder = $apiName
	$isRename = $false
}
if(!(Test-Path -Path $apiPath))
{
   $null = New-Item -Path $apiPath -ItemType Directory
}

# Change the directory to the API path
Set-Location -Path $apiPath

# Create the API project
write-host "[1/10]=========================> Creating the API Project $apiName" -ForegroundColor Yellow
$null=dotnet new webapi --name $apiName --framework net6.0

Set-Location -Path $apiPath\$apiName # Working Directory set to the API project path

$null = dotnet new sln --name $apiName
$slnName = "$apiName.sln"
$csprojName =  "$apiName.csproj"
$null = dotnet sln $slnName add $csprojName
$null = dotnet add $csprojName package NLog.Extensions.Logging --version 5.3.8
$null = dotnet add $csprojName package Anthem.GBD.Medisys.LIB.Logger --version 2023.11.2
$null = dotnet add $csprojName package Microsoft.Data.SqlClient --version 5.2.0
$null = dotnet add $csprojName package Dapper --version 2.1.35
write-host "[2/10]=========================> Solution created Successfully" -ForegroundColor Yellow

# Project workspace structure setup
$workspacePath = Join-Path $apiPath $apiName
$appsettingJsonPath = join-path $workspacePath "appsettings.json"
$DefaultControlsName = $apiName.Split(".")[-1] 
$textinfo = [System.Globalization.CultureInfo]::CurrentCulture.textinfo
$DefaultControlsName = $textinfo.ToTitleCase($DefaultControlsName)
$DefaultBusinessProcessorName = "$($DefaultControlsName)RequestProcessor"
$DefaultBusinessProcessorInterfaceName = "I$($DefaultControlsName)RequestProcessor"
$deployFolderName = $apiRootFolder -split "[.-]" | Select-Object -Last 1 # Need to Correct

# Project Template
#startup.cs file template
$StartupContent = @"
#region Namespace
using $apiName.Common;
using $apiName.App_Start;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using NLog.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using $apiName.Models.Context;
using Anthem.GBD.Medisys.LIB.Logger;
using $apiName.Handlers;
using $apiName.Middlewares;
#endregion
namespace $apiName 
{
    // 
	/// <summary>
	/// Represents the startup class fo the application.
	/// </summary>
	public class Startup
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="Startup"/> class.
		/// </summary>
		/// <param name="configuration">The configuration object.</param>
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}
		/// <summary>
		/// Gets the configuration object.
		/// </summary>
		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		/// <summary>
		/// Configures the serices for the application.
		/// </summary>
		/// <param name="services">The collection of services to configure.</param>
		public void ConfigureServices(IServiceCollection services)
		{
			// AddControllers
			services.AddControllers();
			//Add Controllers with Endpoints
			services.AddControllersWithViews();
			services.AddEndpointsApiExplorer();
			services.AddSwaggerGen();
			// AddHealthChecks
			services.AddHealthChecks();
			// Dependency Injection
			DependencyInjectionConfig.AddScope(services);
			var connectionSection = Configuration.GetSection(ApplicationConstant.ConnectionStringConfigName);
			var storeProcSection = Configuration.GetSection(ApplicationConstant.StoredProcsConfigName);

			services.AddHsts(options =>
			{
				options.Preload = true;
				options.IncludeSubDomains = true;
				options.MaxAge = TimeSpan.FromDays(365);
			});

			//Binding json data into object
			services.Configure<DBContext>(connectionSection);
			services.Configure<StoredProcs>(storeProcSection);
			services.AddMemoryCache();
			// AddCors
			services.AddCors();
			services.Configure<CookiePolicyOptions>(options =>
			{
				options.MinimumSameSitePolicy = SameSiteMode.None;
				options.HttpOnly = HttpOnlyPolicy.Always;
				options.Secure = CookieSecurePolicy.Always;
			});
			services.AddAntiforgery(options =>
			{
				options.HeaderName = ApplicationConstant.XSRFHeaderName;
				options.Cookie.HttpOnly = ApplicationConstant.True;
				options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
				options.Cookie.Expiration = TimeSpan.FromHours(8);
				options.Cookie.Name = ApplicationConstant.XSRFCookieName;
				options.SuppressXFrameOptionsHeader = ApplicationConstant.False;
			});
		}
		/// <summary>
		/// Configure the application's request pipeline.
		/// </summary>
		/// <param name="app"> The application builder.</param>
		/// <param name="env">The web host environment.</param>
		/// <param name="logger">The logger manager.</param>
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerManager logger)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
				app.UseSwagger();
				app.UseSwaggerUI();
			}
			else
			{
				app.ConfigureExceptionHandler(logger, Configuration);
				app.UseHsts();
			}
			app.Use(async (context, next) =>
			{
				context.Response.Headers.Add(ApplicationConstant.XFrameOptions, ApplicationConstant.XFrameOptionsValue);
				context.Response.Headers.Add(ApplicationConstant.XContentTypeOptions, ApplicationConstant.XContentTypeOptionsValue);
				context.Response.Headers.Add(ApplicationConstant.XXssProtection, ApplicationConstant.One);
				context.Response.Headers.Add(ApplicationConstant.ReferrerPolicy, ApplicationConstant.ReferrerPolicyValue);
				context.Response.Headers.Add(ApplicationConstant.XContentSecurityPolicy, ApplicationConstant.XContentSecurityPolicyValue);
				context.Response.Headers.Add(ApplicationConstant.FeaturePolicy, ApplicationConstant.DefaultFeaturePolicy);
				await next();
			});	
			app.UseRouting();
			app.UseMiddleware<RequestMiddleware>();
			app.UseHttpsRedirection();
			app.UseAuthorization();
			app.UseCors( x => x.AllowAnyMethod().AllowAnyHeader().SetIsOriginAllowed(origin => ApplicationConstant.True));
			app.UseEndpoints(endpoints =>
			{
				endpoints.MapHealthChecks("api/$DefaultControlsName/health", new HealthCheckOptions()
				{
					AllowCachingResponses = ApplicationConstant.False
				});
			});
			app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
	}
}
"@
# Program.cs file template
$ProgramContent = @"
#region Namespace
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using NLog.Extensions.Logging;
#endregion
namespace $apiName
{
	/// <summary>
	/// Represents the entry point of the application.
	/// </summary>
	public class Program
	{
		/// <summary>
		/// The main method that is called when the application starts.
		/// </summary>
		/// <param name="args">The command line arguments.</param>
		public static void Main(string[] args)
		{
			CreateHostBuilder(args).Build().Run();
		}

		/// <summary>
		/// Creates an instance of the <see cref="IHostBuilder"/> and configures it.
		/// </summary>
		/// <param name="args">The command line arguments.</param>
		/// <returns>The configured <see cref="IHostBuilder"/>.</returns>
		public static IHostBuilder CreateHostBuilder(string[] args) =>
				Host.CreateDefaultBuilder(args)
				.ConfigureLogging((hostingContext, logging) =>
				{
					logging.AddNLog();
				})
				.ConfigureAppConfiguration(options =>
				{
					options.AddJsonFile("Common/StoredProcs.json", optional: false, reloadOnChange: true);
				})
				.ConfigureWebHostDefaults(webBuilder =>
				{
					webBuilder.UseStartup<Startup>();
				});

	}
}
"@
# DependencyInjectionConfig.cs file template
$DependencyInjectionConfigContent = @"
#region Namespace
using Anthem.GBD.Medisys.LIB.Logger;
using $apiName.Business;
using $apiName.Interfaces;
using Microsoft.Extensions.DependencyInjection;
#endregion
namespace $apiName.App_Start
{
	public class DependencyInjectionConfig
	{
		public static void AddScope(IServiceCollection services)
		{
			services.AddHealthChecks();
			services.AddSingleton<ILoggerManager, LoggerManager>();
			services.AddHttpClient();
			services.AddMemoryCache();
		}
	}
}
"@
# Default API  BusinessProcessor.cs file template
$DefaultBusinessProcessorContent = @"
#region Namespace
using $apiName.Interfaces;
using $apiName.Models;
using System;
using System.Collections.Generic;
using System.Linq;
#endregion
namespace $apiName.Business
{
	public class $DefaultBusinessProcessorName : I$DefaultBusinessProcessorName
	{
		public $DefaultBusinessProcessorName() { }

	}
}
"@
# Default API  BusinessProcessorInterface.cs file template
$DefaultBusinessProcessorInterfaceContent = @"
#region Namespace
using $apiName.Models;
#endregion

namespace $apiName.Interfaces
{
	public interface I$DefaultBusinessProcessorName
	{
		
	}
}
"@
# Common ApplicationConstant.cs file template
$ApplicationConstantContent = @"
namespace $apiName.Common
{
	public static class ApplicationConstant
	{
		//Content Types
		public const string ContentTypeJson = "application/json";
		public const string ContentTypeXml = "application/xml";
		public const string ContentTypeFormUrlEncoded = "application/x-www-form-urlencoded";
		public const string ContentTypeTextPlain = "text/plain";
		public const string ContentTypeTextHtml = "text/html";
		public const string ContentTypeTextXml = "text/xml";
		public const string ContentTypeTextJson = "text/json";

		//Security Header names
		public const string XFrameOptions = "X-Frame-Options";
		public const string XFrameOptionsValue = "DENY";
		public const string XContentTypeOptions = "X-Content-Type-Options";
		public const string XContentTypeOptionsValue = "nosniff";
		public const string XContentSecurityPolicy = "Content-Security-Policy";
		public const string XContentSecurityPolicyValue = "default-src 'self'";
		public const string ReferrerPolicy = "Referrer-Policy";
		public const string ReferrerPolicyValue = "no-referrer";
		public const string FeaturePolicy = "Feature-Policy";
		public const string DefaultFeaturePolicy = "Default";
		//XSS protection header
		public const string XXssProtection = "X-XSS-Protection";
		public const string One = "1";

		// Yes(Y) or No(N) in char
		public const string Y = "Y";
		public const string N = "N";
		// Yes(YES) or No(NO) in string
		public const string Yes = "YES";
		public const string No = "NO";

		// True and false in string
		public const bool True = true;
		public const bool False = false;

		public const string XSRFHeaderName = "X-XSRF-TOKEN";
		public const string XSRFCookieName = "XSRF-TOKEN";
		
		// Default connection string 
		public const string ConnectionStringConfigName = "ConnectionStrings";
		public const string DefaultConnectionConfigName = "DefaultConnection";
		public const string StoredProcsConfigName = "StoredProcs";
		public const string IsLoggingEnabledConfigName = "IsLoggingEnabled";

	}
}
"@
# StoredProcs.json file template
$StoredProcsJsonContent = @"
{
	"StoreProcs": {
		"StoreProc": [
			{
				"key": "",
				"value": ""
			}
		]
	}
}
"@
# Common StoredProcs.cs file template
$StoredProcsContent = @"
namespace $apiName.Common
{
	/// <summary>
	/// Represents a collection of stored procedures.
	/// </summary>
	public class StoredProcs
	{
		/// <summary>
		/// Gets or sets the list of stored procedures configurations.
		/// </summary>
        public List<StoreProcConfig> StoreProc { get; set; }
    }
	/// <summary>
	/// Represents a configuration for a stored procedure.
	/// </summary>
	public class StoreProcConfig
	{
		/// <summary>
		/// Gets or sets the key of the stored procedure configuration.
		/// </summary>
        public string Key { get; set; }
		/// <summary>
		/// Gets or sets the value of the stored procedure configuration.
		/// </summary>
		public string Value { get; set; }
    }
}
"@
# ExceptionHandlerMiddleware.cs file template
$ExceptionHandlerContent = @"
#region Namespace
using Anthem.GBD.Medisys.LIB.Logger;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using $apiName.Common;
using Microsoft.Data.SqlClient;
#endregion

namespace $apiName.Handlers
{
	/// <summary>
	/// Provides a static class for configuring the exception handler for the application.
	/// </summary>
	public static class ExceptionHandler
	{
		/// <summary>
		/// Indicates whether logging is enabled or not.
		/// </summary>
		private static string isLoggingEnabled = ApplicationConstant.N;

		/// <summary>
		/// Configure the exception handler for the application.
		/// </summary>
		/// <param name="app">The <see cref="IApplicationBuilder"/> instance.</param>
		/// <param name="logger">The <see cref="ILoggerManager"/> instance.</param>
		/// <param name="configuration">The <see cref="IConfiguration"/> instance.</param>
		public static void ConfigureExceptionHandler(this IApplicationBuilder app, ILoggerManager logger, IConfiguration configuration)
		{
			try
			{
				app.UseExceptionHandler(appError =>
				{
					appError.Run(async context =>
					{
						context.Response.ContentType = ApplicationConstant.ContentTypeJson;
						var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
						if (contextFeature != null)
						{
							isLoggingEnabled = configuration.GetValue<string>("IsLoggingEnabled");
							
							NLog.LogEventInfo eventInfo = new NLog.LogEventInfo(NLog.LogLevel.Error, "${$DefaultControlsName}", "");
							eventInfo.Properties["callerId"] = context.Request.Headers["CallerID"];
							
							if(!Utility.IsNullOrEmpty(isLoggingEnabled) && Utility.IsEqual(ApplicationConstant.Y, isLoggingEnabled))
							{
								using var streamReader = new StreamReader(context.Request.Body);
								streamReader.BaseStream.Seek(0, SeekOrigin.Begin);
								var requestBody = await streamReader.ReadToEndAsync();
								var formattedRequestBody = $"{context.Request.Scheme} {context.Request.Host} {context.Request.Path} {context.Request.QueryString} {requestBody}";
								eventInfo.Properties["requestBody"] = formattedRequestBody;
							}
							eventInfo.Exception = contextFeature.Error;
							logger.Log(eventInfo);

							string errorMessage = (string)GetErrorMessage(contextFeature.Error);

							await context.Response.WriteAsync(new ErrorDetails()
							{
								StatusCode = context.Response.StatusCode,
								Message = errorMessage,
								Severity = "E",
								Process = ".NET CORE Provider PayMethod Service"

							}.ToString());
						}
					});
				});
			}
			catch (Exception ex)
			{
				throw ex;
			}
		}
		/// <summary>
		/// Gets the custom error message based on the provided exception
		/// </summary>
		/// <param name="exception">The exception.</param>
		/// <returns>The custom error message</returns>
		private static string GetErrorMessage(Exception exception)
		{
			string errorMessage = string.Empty;
			switch(exception)
			{
				case Exception ex when ex is ArgumentNullException:
					errorMessage = "Invalid request input";
					break;
				case Exception ex when ex is ArgumentException:
					errorMessage = "Invalid request input";
					break;
				case Exception ex when ex is UnauthorizedAccessException:
					errorMessage = "Unauthorized request";
					break;
				case Exception ex when ex is IOException:
					errorMessage = "Input/Output failure";
					break;
				case Exception ex when ex is SystemException:
					errorMessage = "System failure";
					break;
				case Exception ex when ex is ApplicationException:
					errorMessage = "Application failure";
					break;
				case Exception ex when ex is Exception:
					errorMessage = "Techincal service failure";
					break;
				case Exception ex when ex is NotImplementedException:
					errorMessage = "Invalid operation";
					break;
				case Exception ex when ex is AggregateException:
					errorMessage = "Invalid aggregation";
					break;
				case Exception ex when ex is NullReferenceException:
					errorMessage = "Techincal service failure";
					break;
				case Exception ex when ex is UriFormatException:
					errorMessage = "Invalid URI format";
					break;
				//formatexception
				case Exception ex when ex is FormatException:
					errorMessage = "Invalid format";
					break;
				//timeoutexception
				case Exception ex when ex is TimeoutException:
					errorMessage = "Operation timeout";
					break;
				//outofmemoryexception
				case Exception ex when ex is OutOfMemoryException:
					errorMessage = "Running out of memory";
					break;
				//IndexOutOfRangeException
				case Exception ex when ex is IndexOutOfRangeException:
					errorMessage = "Invalid access of range";
					break;
				// Sql Exception
				case Exception ex when ex is SqlException:
					errorMessage = "Infrastructure error";
					break;
				default:
					errorMessage = "Operation failed";
					break;
			}	
			return errorMessage;
		}
	}
}
"@

# RequestMiddleware.cs file template
$RequestMiddlewareContent = @"
#region Namespace
using System;
using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Anthem.GBD.Medisys.LIB.Logger;
using $apiName.Common;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NLog;
#endregion
namespace $apiName.Middlewares
{	
	/// <summary>
	/// Middleware for handling incoming HTTP requests.
	/// </summary>
	public class RequestMiddleware
	{
		/// <summary>
		/// Represents a middleware that handles incoming requests.
		/// </summary>
		private readonly RequestDelegate _next;
		/// <summary>
		/// 
		/// </summary>
		private readonly ILoggerManager _logger;
		/// <summary>
		/// Indicates whether logging is enabled or not.
		/// </summary>
		private string isLoggingEnabled = ApplicationConstant.N;
		/// <summary>
		/// Initializes a new instance of the <see cref="RequestMiddleware"/> class.
		/// </summary>
		/// <param name="next">The request delegate.</param>
		/// <param name="logger">The logger.</param>
		/// <param name="configuration">The configuration.</param>
		public RequestMiddleware(RequestDelegate next, ILoggerManager logger, IConfiguration configuration)
		{
			_next = next;
			_logger = logger;
			isLoggingEnabled = configuration.GetValue<string>(ApplicationConstant.IsLoggingEnabledConfigName);
		}
		/// <summary>
		/// Represents an asynchronous operation that handles the incoming HTTP request.
		/// </summary>
		/// <param name="context">The HttpContext representing the current HTTP request.</param>
		/// <returns>A task that represents the asynchronous operation.</returns>
		public async Task Invoke(HttpContext context)
		{
			try
			{
				if (!Utility.IsNullOrEmpty(isLoggingEnabled) && Utility.IsEqual(ApplicationConstant.Y, isLoggingEnabled))
				{
					context.Request.EnableBuffering();
					var builder = new StringBuilder();
					using var reader = new StreamReader(context.Request.Body, encoding: Encoding.UTF8, detectEncodingFromByteOrderMarks: ApplicationConstant.False, leaveOpen: ApplicationConstant.True);
					context.Request.Body.Position = 0;
				}
				await _next(context);
			}
			catch (Exception ex)
			{
				LogEventInfo eventInfo = new LogEventInfo(NLog.LogLevel.Error, "$($DefaultControlsName)Log", ex.Message);
				eventInfo.Properties["callerId"] = context.Request.Headers["CallerID"];
				_logger.Log(eventInfo);
				throw;
			}
		}

	}
}
"@
# DBContext.cs file template
$DBContextContent = @"
#region Namespace
using System.Collections.Generic;
#endregion
namespace $apiName.Models.Context
{
	/// <summary>
	/// Represents the database context for the application.
	/// </summary>
	public class DBContext
	{
		/// <summary>
		/// Gets or sets the default connection string.
		/// </summary>
        public string DefaultConnection { get; set; }
    }
}
"@
# ErrorDetails.cs file template
$CommonErrorDetailsContent = @"
#region Namespace
using System.Text.Json;
#endregion
namespace $apiName.Common
{
	public class ErrorDetails
	{
        public int StatusCode { get; set; }
        public string? Message { get; set; }
        public string? Severity { get; set; }
        public string? Process { get; set; }
		public override string ToString()
		{
			return JsonSerializer.Serialize(this);
		}

	}
    
}
"@
# Common Utility.cs file template
$CommonUtilityContent = @"
namespace $apiName.Common
{
	public static class Utility
	{
	
		/// <summary>
		/// Check the given string is null or empty
		/// </summary>
		/// <param name="value">value</param>
		/// <returns></returns>
		public static bool IsNullOrEmpty(string value)
		{
			return (value == null || value.Trim().Equals(string.Empty));
		}
		// Compare source and target strings is equal or not
		public static bool IsEqual(string sourceValue, string compareValue)
		{
			bool isEqual = ApplicationConstant.False;
			if(!IsNullOrEmpty(sourceValue) && !IsNullOrEmpty(compareValue))
			{
				sourceValue = sourceValue.ToUpper();
				compareValue = compareValue.ToUpper();
				isEqual = sourceValue.Equals(compareValue);
			}
			return isEqual;
		}
		
	}
}
"@
# Model request.cs file template
$ModelRequestContent = @"
namespace $apiName.Models
{
	public class $($DefaultControlsName)Request
	{

	}
}
"@
# Model Response.cs file template
$ModelResponseContent = @"
namespace $apiName.Models
{
    public class $($DefaultControlsName)Response
    {

    }
}
"@
# BaseValidator.cs file template
$BaseValidatorContent = @"
namespace $apiName.Validator
{
	public class BaseValidator
	{
	}
}
"@
# Default Repository.cs file template
$RepositorieContent = @"
namespace $apiName.Repositories
{
    public class $($DefaultControlsName)Repository
    {
    }
}
"@
# AntiforgeryController.cs file template
$AddAntiforgeryContent = @"
#region Namespace
using Anthem.GBD.Medisys.LIB.Logger;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Text.Json;
#endregion
namespace $apiName.Controllers
{
	/// <summary>
	/// Represents a controller for handling anti-forgery tokens for protection.
	/// </summary>
	[Route("api/[controller]/[action]")]
	[ApiController]
	public class AntiForgeryController : ControllerBase
	{
		private readonly ILoggerManager _logger;
		private readonly IAntiforgery _antiforgery;
		public AntiForgeryController(IAntiforgery antiforgery,ILoggerManager logger)
		{
			_antiforgery = antiforgery;
			_logger = logger;
		}
		/// <summary>
		/// IsAlive - Check API is Up or Down
		/// </summary>
		/// <returns>true if the API is up and running</returns> 
		[HttpGet]
		[ActionName("IsAlive")]
		public ActionResult<bool> IsAlive()
		{
			return true;
		}

		/// <summary>
		/// Retrieves an anti-forgery token.
		/// </summary>
		/// <returns>The anti-forgery token as a string.</returns>
		[HttpGet]
		[ActionName("GetToken")]
		public ActionResult<string> GetToken()
		{
			_logger.Info("$($DefaultControlsName) : GetToken - Initialized");
			try
			{
				var token = _antiforgery.GetAndStoreTokens(HttpContext);
				var response =  JsonSerializer.Serialize(token.RequestToken);
				return Content(response);
			}
			catch (Exception ex)
			{
				_logger.Error(string.Format("$($DefaultControlsName) : GetToken - Exception on activity endpoint for request. Exception: {0}", ex.ToString()));
				return new StatusCodeResult(StatusCodes.Status500InternalServerError);
			}
		}
	
	}
}
"@

# appsettings.json file template
$AppSettingsContent = @"
{
  "ConnectionStrings": {
    "DefaultConnection": "Data Source=sqlmedisysdev2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=member;TrustServerCertificate=true;Trusted_Connection=Yes;Integrated Security=True;"

  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "AllowedHosts": "*",
  "Services": {
    "GatewayService": "https://localhost:44341",
    "GatewayDirectory": "/MedisysAPIGateway"
  },
  "Config": {
    "SMTPServer": "smtprelay1.aici.com",
    "FromMail": "Medisys@wellpoint.com",
    "ToMail": "AG44541@wellpoint.com"
  },
  "IsLoggingEnabled": "Y"
}
"@
# Environment specific appsettings.json file template
$EnvLevle =@"
[
    {
        "DEV2\\App":  {
                          "GatewayDirectory":  "/MedisysAPIGateway",
                          "ConnectionString":  "Data Source=sqlmedisysdev2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                          "GatewayService":  "https://va10n50577.us.ad.wellpoint.com"
                      }
    },
    {
        "DEV2\\Batch":  {
                            "GatewayDirectory":  "/MedisysAPIGateway",
                            "ConnectionString":  "Data Source=sqlmedisysdev2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                            "GatewayService":  "https://va10n50644.us.ad.wellpoint.com"
                        }
    },
    {
        "DEV3\\App":  {
                          "GatewayDirectory":  "/MedisysAPIGateway",
                          "ConnectionString":  "Data Source=sqlmedisysdev3.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                          "GatewayService":  "https://va10n50577.us.ad.wellpoint.com"
                      }
    },
    {
        "DEV3\\Batch":  {
                            "GatewayDirectory":  "/MedisysAPIGateway",
                            "ConnectionString":  "Data Source=sqlmedisysdev3.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                            "GatewayService":  "https://va10n50577.us.ad.wellpoint.com"
                        }
    },
    {
        "Missouri\\App":  {
                              "GatewayDirectory":  "/MedisysAPIGateway",
                              "ConnectionString":  "Data Source=sqlmedisysstaging.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=member;Trusted_Connection=Yes",
                              "GatewayService":  "https://MOM9TWVISS307.us.ad.wellpoint.com"
                          }
    },
    {
        "Missouri\\Batch":  {
                                "GatewayDirectory":  "/MedisysAPIGateway",
                                "ConnectionString":  "Data Source=sqlmedisysstaging.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                                "GatewayService":  "https://MOM9TWVISS308.us.ad.wellpoint.com"
                            }
    },
    {
        "PERF\\PERF\\App":  {
                                "GatewayDirectory":  "/MedisysAPIGateway",
                                "ConnectionString":  "Data Source=sqlmedisysperf.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                                "GatewayService":  "https://medisysb.wellpoint.com"
                            }
    },
    {
        "PERF\\PERF\\Batch":  {
                                  "GatewayDirectory":  "/MedisysAPIGateway",
                                  "ConnectionString":  "Data Source=sqlmedisysperf.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                                  "GatewayService":  "https://VA10TWVISS345.wellpoint.com"
                              }
    },
    {
        "PERF\\PERF\\Batch\\VA10TWVISS535":  {
                                                 "GatewayDirectory":  "/MedisysAPIGateway",
                                                 "ConnectionString":  "Data Source=sqlmedisysperf.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                                                 "GatewayService":  "https://VA10TWVISS535.wellpoint.com"
                                             }
    },
    {
        "PERF\\PERFRO\\App":  {
                                  "GatewayDirectory":  "/MedisysAPIGateway",
                                  "ConnectionString":  "Data Source=sqlmedisysperf.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                                  "GatewayService":  "https://va33twviss545.wellpoint.com"
                              }
    },
    {
        "PROD\\PROD\\App":  {
                                "GatewayDirectory":  "/MedisysAPIGateway",
                                "ConnectionString":  "Please provide the prod connection string here",
                                "GatewayService":  "Please provide the prod gateway service here"
                            }
    },
    {
        "PROD\\PROD\\Batch\\VA10PWVISS1067":  {
                                                  "GatewayDirectory":  "/MedisysAPIGateway",
                                                  "ConnectionString":  "Please provide the prod connection string here",
                                                  "GatewayService":  "Please provide the prod gateway service here"
                                              }
    },
    {
        "PROD\\PROD\\Batch\\VA10PWVISS347":  {
                                                 "GatewayDirectory":  "/MedisysAPIGateway",
                                                 "ConnectionString":  "Please provide the prod connection string here",
                                                 "GatewayService":  "Please provide the prod gateway service here"
                                             }
    },
    {
        "PROD\\PROD\\Batch\\VA10PWVISS348":  {
                                                 "GatewayDirectory":  "/MedisysAPIGateway",
                                                 "ConnectionString":  "Please provide the prod connection string here",
                                                 "GatewayService":  "Please provide the prod gateway service here"
                                             }
    },
    {
        "PROD\\PRODRO\\App":  {
                                  "GatewayDirectory":  "/MedisysAPIGateway",
                                  "ConnectionString":  "Please provide the prod connection string here",
                                  "GatewayService":  "Please provide the prod gateway service here"
                              }
    },
    {
        "SIT2\\App":  {
                          "GatewayDirectory":  "/MedisysAPIGateway",
                          "ConnectionString":  "Data Source=sqlmedisyssit2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                          "GatewayService":  "https://VA10TWVISS333.us.ad.wellpoint.com:444"
                      }
    },
    {
        "SIT2\\Batch":  {
                            "GatewayDirectory":  "/MedisysAPIGateway",
                            "ConnectionString":  "Data Source=sqlmedisyssit2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                            "GatewayService":  "https://VA10TWVISS337.us.ad.wellpoint.com"
                        }
    },
    {
        "SIT3\\App":  {
                          "GatewayDirectory":  "/MedisysAPIGateway",
                          "ConnectionString":  "Data Source=sqlmedisyssit3.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                          "GatewayService":  "https://VA10TWVISS335.us.ad.wellpoint.com"
                      }
    },
    {
        "SIT3\\Batch":  {
                            "GatewayDirectory":  "/MedisysAPIGateway",
                            "ConnectionString":  "Data Source=sqlmedisyssit3.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                            "GatewayService":  "https://VA10TWVISS332.us.ad.wellpoint.com"
                        }
    },
    {
        "UAT1\\App":  {
                          "GatewayDirectory":  "/MedisysAPIGateway",
                          "ConnectionString":  "Data Source=sqlmedisysuat1.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                          "GatewayService":  "https://VA10TWVISS348.us.ad.wellpoint.com:444"
                      }
    },
    {
        "UAT1\\Batch":  {
                            "GatewayDirectory":  "/MedisysAPIGateway",
                            "ConnectionString":  "Data Source=sqlmedisysuat1.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                            "GatewayService":  "https://VA10TWVISS330.us.ad.wellpoint.com"
                        }
    },
    {
        "UAT2\\App":  {
                          "GatewayDirectory":  "/MedisysAPIGateway",
                          "ConnectionString":  "Data Source=sqlmedisysuat2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                          "GatewayService":  "https://VA10TWVISS328.us.ad.wellpoint.com"
                      }
    },
    {
        "UAT2\\Batch":  {
                            "GatewayDirectory":  "/MedisysAPIGateway",
                            "ConnectionString":  "Data Source=sqlmedisysuat2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                            "GatewayService":  "https://VA10TWVISS331.us.ad.wellpoint.com"
                        }
    },
    {
        "UAT3\\App":  {
                          "GatewayDirectory":  "/MedisysAPIGateway",
                          "ConnectionString":  "Data Source=sqlmedisysuat3.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                          "GatewayService":  "https://va33twviss603.devad.wellpoint.com"
                      }
    },
    {
        "UAT3\\Batch":  {
                            "GatewayDirectory":  "/MedisysAPIGateway",
                            "ConnectionString":  "Data Source=sqlmedisysuat3.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=stat_his;Trusted_Connection=Yes",
                            "GatewayService":  "https://va33twviss605.devad.wellpoint.com"
                        }
    }
]
"@
# gitignore file template
$gitIgnoreContent = @"
## Ignore Visual Studio temporary files, build results, and
## files generated by popular Visual Studio add-ons.
##
## Get latest from https://github.com/github/gitignore/blob/master/VisualStudio.gitignore

# User-specific files
*.suo
*.user
*.userosscache
*.sln.docstates

# User-specific files (MonoDevelop/Xamarin Studio)
*.userprefs

# Build results
[Dd]ebug/
[Dd]ebugPublic/
[Rr]elease/
[Rr]eleases/
x64/
x86/
bld/
[Bb]in/
[Oo]bj/
[Ll]og/

# Visual Studio 2015/2017 cache/options directory
.vs/
# Uncomment if you have tasks that create the project's static files in wwwroot
#wwwroot/

# Visual Studio 2017 auto generated files
Generated\ Files/

# MSTest test Results
[Tt]est[Rr]esult*/
[Bb]uild[Ll]og.*

# NUNIT
*.VisualState.xml
TestResult.xml

# Build Results of an ATL Project
[Dd]ebugPS/
[Rr]eleasePS/
dlldata.c

# Benchmark Results
BenchmarkDotNet.Artifacts/

# .NET Core
project.lock.json
project.fragment.lock.json
artifacts/

# StyleCop
StyleCopReport.xml

# Files built by Visual Studio
*_i.c
*_p.c
*_i.h
*.ilk
*.meta
*.obj
*.iobj
*.pch
*.pdb
*.ipdb
*.pgc
*.pgd
*.rsp
*.sbr
*.tlb
*.tli
*.tlh
*.tmp
*.tmp_proj
*.log
*.vspscc
*.vssscc
.builds
*.pidb
*.svclog
*.scc

# Chutzpah Test files
_Chutzpah*

# Visual C++ cache files
ipch/
*.aps
*.ncb
*.opendb
*.opensdf
*.sdf
*.cachefile
*.VC.db
*.VC.VC.opendb

# Visual Studio profiler
*.psess
*.vsp
*.vspx
*.sap

# Visual Studio Trace Files
*.e2e

# TFS 2012 Local Workspace
`$tf/

# Guidance Automation Toolkit
*.gpState

# ReSharper is a .NET coding add-in
_ReSharper*/
*.[Rr]e[Ss]harper
*.DotSettings.user

# JustCode is a .NET coding add-in
.JustCode

# TeamCity is a build add-in
_TeamCity*

# DotCover is a Code Coverage Tool
*.dotCover

# AxoCover is a Code Coverage Tool
.axoCover/*
!.axoCover/settings.json

# Visual Studio code coverage results
*.coverage
*.coveragexml

# NCrunch
_NCrunch_*
.*crunch*.local.xml
nCrunchTemp_*

# MightyMoose
*.mm.*
AutoTest.Net/

# Web workbench (sass)
.sass-cache/

# Installshield output folder
[Ee]xpress/

# DocProject is a documentation generator add-in
DocProject/buildhelp/
DocProject/Help/*.HxT
DocProject/Help/*.HxC
DocProject/Help/*.hhc
DocProject/Help/*.hhk
DocProject/Help/*.hhp
DocProject/Help/Html2
DocProject/Help/html

# Click-Once directory
publish/

# Publish Web Output
*.[Pp]ublish.xml
*.azurePubxml
# Note: Comment the next line if you want to checkin your web deploy settings,
# but database connection strings (with potential passwords) will be unencrypted
# *.pubxml
*.publishproj

# Microsoft Azure Web App publish settings. Comment the next line if you want to
# checkin your Azure Web App publish settings, but sensitive information contained
# in these scripts will be unencrypted
PublishScripts/

# NuGet Packages
*.nupkg
# The packages folder can be ignored because of Package Restore
**/[Pp]ackages/*
# except build/, which is used as an MSBuild target.
!**/[Pp]ackages/build/
# Uncomment if necessary however generally it will be regenerated when needed
#!**/[Pp]ackages/repositories.config
# NuGet v3's project.json files produces more ignorable files
*.nuget.props
*.nuget.targets

# Microsoft Azure Build Output
csx/
*.build.csdef

# Microsoft Azure Emulator
ecf/
rcf/

# Windows Store app package directories and files
AppPackages/
BundleArtifacts/
Package.StoreAssociation.xml
_pkginfo.txt
*.appx

# Visual Studio cache files
# files ending in .cache can be ignored
*.[Cc]ache
# but keep track of directories ending in .cache
!*.[Cc]ache/

# Others
ClientBin/
~$*
*~
*.dbmdl
*.dbproj.schemaview
*.jfm
*.pfx
*.publishsettings
orleans.codegen.cs

# Including strong name files can present a security risk
# (https://github.com/github/gitignore/pull/2483#issue-259490424)
#*.snk

# Since there are multiple workflows, uncomment next line to ignore bower_components
# (https://github.com/github/gitignore/pull/1529#issuecomment-104372622)
#bower_components/

# RIA/Silverlight projects
Generated_Code/

# Backup & report files from converting an old project file
# to a newer Visual Studio version. Backup files are not needed,
# because we have git ;-)
_UpgradeReport_Files/
Backup*/
UpgradeLog*.XML
UpgradeLog*.htm
ServiceFabricBackup/
*.rptproj.bak

# SQL Server files
*.mdf
*.ldf
*.ndf

# Business Intelligence projects
*.rdl.data
*.bim.layout
*.bim_*.settings
*.rptproj.rsuser

# Microsoft Fakes
FakesAssemblies/

# GhostDoc plugin setting file
*.GhostDoc.xml

# Node.js Tools for Visual Studio
.ntvs_analysis.dat
node_modules/

# Visual Studio 6 build log
*.plg

# Visual Studio 6 workspace options file
*.opt

# Visual Studio 6 auto-generated workspace file (contains which files were open etc.)
*.vbw

# Visual Studio LightSwitch build output
**/*.HTMLClient/GeneratedArtifacts
**/*.DesktopClient/GeneratedArtifacts
**/*.DesktopClient/ModelManifest.xml
**/*.Server/GeneratedArtifacts
**/*.Server/ModelManifest.xml
_Pvt_Extensions

# Paket dependency manager
.paket/paket.exe
paket-files/

# FAKE - F# Make
.fake/

# JetBrains Rider
.idea/
*.sln.iml

# CodeRush
.cr/

# Python Tools for Visual Studio (PTVS)
__pycache__/
*.pyc

# Cake - Uncomment if you are using it
# tools/**
# !tools/packages.config

# Tabs Studio
*.tss

# Telerik's JustMock configuration file
*.jmconfig

# BizTalk build output
*.btp.cs
*.btm.cs
*.odx.cs
*.xsd.cs

# OpenCover UI analysis results
OpenCover/

# Azure Stream Analytics local run output
ASALocalRun/

# MSBuild Binary and Structured Log
*.binlog

# NVidia Nsight GPU debugger configuration file
*.nvuser

# MFractors (Xamarin productivity tool) working folder
.mfractor/

*.exe
*_i.c
*_p.c
*.ncb
*.suo
*.tlb
*.tlh
*.bak
*.cache
*.ilk
*.log
*.dll
*.lib
*.sbr
*.zip
*.scc
*.vspscc
*.vssscc
*.ccexclude
*.copyarea.db
Thumbs.db
*.orig
bin/
obj/
/Medisys_Solution/Anthem.SB.Medisys/.vs
/Medisys_Solution/Anthem.SB.Medisys/packages
/Solutions/.vs
/Solutions/packages

/DAR
*.dar

# Excluded the direct reference assemblies until NUGET reference is implemented .
!Medisys_Solution/Anthem.SB.Medisys/ReferenceAssemblies/*.dll

# compiled output  
/dist  
/tmp  
/out-tsc  
  
# dependencies  
/node_modules  
  
# IDEs and editors  
/.idea  
.project  
.classpath  
.c9/  
*.launch  
.settings/  
*.sublime-workspace  
  
# IDE - VSCode  
.vscode/*  
!.vscode/settings.json  
!.vscode/tasks.json  
!.vscode/launch.json  
!.vscode/extensions.json  
  
# misc  
/.sass-cache  
/connect.lock  
/coverage  
/libpeerconnection.log  
npm-debug.log  
yarn-error.log  
testem.log  
/typings  
  
# System Files  
.DS_Store 
"@
# build propertites template file
$buildPropertyontent=@"
xldappPath=Applications/enrollment-platforms/unknown/unknown/medisys/Core-mbrDtl
xldenvDEV2=NONE
xldenvSIT2App=Environments/SIT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-SIT2-App
xldenvSIT2Batch=Environments/SIT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-SIT2-Batch
xldenvSIT3App=Environments/SIT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-SIT3-App
xldenvSIT3Batch=Environments/SIT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-SIT3-Batch
xldenvUAT1App=Environments/UAT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-UAT1-App
xldenvUAT1Batch=Environments/UAT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-UAT1-Batch
xldenvUAT2App=Environments/UAT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-UAT2-App
xldenvUAT2Batch=Environments/UAT/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-UAT2-Batch
xldenvMissouriApp=NONE
xldenvMissouriBatch=NONE
xldenvPERF343=Environments/PERF/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PERF-343
xldenvPERF344=Environments/PERF/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PERF-344
xldenvPERF346=Environments/PERF/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PERF-346
xldenvPERF345=Environments/PERF/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PERF-345
xldenvPERFR545=NONE
xldenvPROD345=Environments/PROD/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PROD-345
xldenvPROD346=Environments/PROD/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PROD-346
xldenvPROD342=Environments/PROD/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PROD-342
xldenvPROD347=Environments/PROD/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PROD-347
xldenvPROD348=Environments/PROD/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PROD-348
xldenvPRODR850=Environments/PROD/enrollment-platforms/unknown/unknown/medisys/App-Batch/mbrDtl-PRODRO-850
xldserviceID=srcMedisysBuild
"@
# deploy manifest template file
$deployManifestContent = @"
<?xml version="1.0" encoding="UTF-8"?>
<udm.DeploymentPackage version="1" application="Core-mbrDtl">
	<application />
	<orchestrator>
		<value>sequential-by-deployed</value>
	</orchestrator>
	<deployables>
		<file.File  name="001-Copy_mbrDtl_stop_start_app_pool.ps1" file="DeploymentFiles/IIS/stop_start_app_pool.ps1">
			<tags>
				<value>DEV2</value>
				<value>DEV3</value>
				<value>SIT2</value>
				<value>SIT3</value>
				<value>UAT1</value>
				<value>UAT2</value>
				<value>PERF</value>
				<value>Missouri</value>
				<value>Trng</value>
				<value>PROD</value>
			</tags>
			<targetPath>{{XL_Targetpath}}</targetPath>
			<targetFileName>stop_start_app_pool.ps1</targetFileName>
			<scanPlaceholders>true</scanPlaceholders>
			<preScannedPlaceholders>true</preScannedPlaceholders>
			<checksum></checksum>
		</file.File>
		<cmd.Command name="002-mbrDtl_stop_apppool">
			<commandLine>powershell `${001-Copy_mbrDtl_stop_start_app_pool.ps1} -applicationPoolName {{IIS_mbrDtl}} -Action {{Action_Application_Pool_Stop}}</commandLine>
			<order>24</order>
			<dependencies>
				<ci ref="001-Copy_mbrDtl_stop_start_app_pool.ps1"/> 
			</dependencies>
			<undoOrder>26</undoOrder>
			<undoCommandLine></undoCommandLine>
			<undoDependencies/>
			<runUndoCommandOnUpgrade>true</runUndoCommandOnUpgrade>
			<tags>
				<value>DEV2</value>
				<value>DEV3</value>
				<value>SIT2</value>
				<value>SIT3</value>
				<value>UAT1</value>
				<value>UAT2</value>
				<value>PERF</value>
				<value>Missouri</value>
				<value>Trng</value>
				<value>PROD</value>
			</tags>
		</cmd.Command>
		<cmd.Command name="003-WaitTimembrDtl1">
			<order>25</order>
			<undoOrder>26</undoOrder>
			<commandLine>powershell Start-Sleep -Seconds {{WaitTimembrDtl1}}</commandLine>
			<undoCommandLine></undoCommandLine>
			<tags>
				<value>DEV2</value>
				<value>DEV3</value>
				<value>SIT2</value>
				<value>SIT3</value>
				<value>UAT1</value>
				<value>UAT2</value>
				<value>PERF</value>
				<value>Missouri</value>
				<value>Trng</value>
				<value>PROD</value>
			</tags>
		</cmd.Command>
		<cmd.Command name="003-WaitTimembrDtl2">
			<order>25</order>
			<undoOrder>26</undoOrder>
			<commandLine>powershell Start-Sleep -Seconds {{WaitTimembrDtl2}}</commandLine>
			<undoCommandLine></undoCommandLine>
			<tags>
				<value>DEV2</value>
				<value>DEV3</value>
				<value>SIT2</value>
				<value>SIT3</value>
				<value>UAT1</value>
				<value>UAT2</value>
				<value>PERF</value>
				<value>Missouri</value>
				<value>Trng</value>
				<value>PROD</value>
			</tags>
		</cmd.Command>
		<cmd.Command name="004-mbrDtlBackup">
			<order>26</order>
			<undoOrder>26</undoOrder>
			<commandLine>powershell Copy-Item -Path {{targetmbrDtlPath}}\ -Destination (new-item {{angularBackupPath}}\mbrDtl`$(get-date -f MM-dd-yyyy_HH_mm_ss) -ItemType Directory -Force) -Recurse</commandLine>
			<undoCommandLine></undoCommandLine>
			<runUndoCommandOnUpgrade>true</runUndoCommandOnUpgrade>
			<tags>
				<value>DEV2</value>
				<value>DEV3</value>
				<value>SIT2</value>
				<value>SIT3</value>
				<value>UAT1</value>
				<value>UAT2</value>
				<value>PERF</value>
				<value>Missouri</value>
				<value>Trng</value>
				<value>PROD</value>
			</tags>
		</cmd.Command>
		<cmd.Command name="005-Remove_mbrDtl_Binaries">
			<order>26</order>
			<undoOrder>26</undoOrder>
			<commandLine>powershell if(Test-Path {{targetmbrDtlPath}} ){Remove-Item {{targetmbrDtlPath}}\*  -Force -Recurse -ErrorAction SilentlyContinue }</commandLine>
			<undoCommandLine></undoCommandLine>
			<runUndoCommandOnUpgrade>true</runUndoCommandOnUpgrade>
			<tags>
				<value>DEV2</value>
				<value>DEV3</value>
				<value>SIT2</value>
				<value>SIT3</value>
				<value>UAT1</value>
				<value>UAT2</value>
				<value>PERF</value>
				<value>Missouri</value>
				<value>Trng</value>
				<value>PROD</value>
			</tags>
		</cmd.Command>
		<file.Folder name="006-Copy_mbrDtl_Binaries" file="DeploymentFiles/build">
			<tags>
				<value>mbrDtl_Binaries</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<checksum></checksum>
		</file.Folder>

		<file.File name="DEV2_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/DEV2/App/appsettings.json">
			<tags>
				<value>DEV2_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="DEV2_Copy_mbrDtl_Batch_appsettings_json" file="DeploymentFiles/Medisys_Configurations/DEV2/Batch/appsettings.json">
			<tags>
				<value>DEV2_Copy_mbrDtl__Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>

		<file.File name="DEV3_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/DEV3/App/appsettings.json">
			<tags>
				<value>DEV3_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="DEV3_Copy_mbrDtl_Batch_appsettings_json" file="DeploymentFiles/Medisys_Configurations/DEV3/Batch/appsettings.json">
			<tags>
				<value>DEV3_Copy_mbrDtl_Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>

		<file.File name="SIT2_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/SIT2/App/appsettings.json">
			<tags>
				<value>SIT2_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="SIT2_Copy_mbrDtl_Batch_appsettings_json" file="DeploymentFiles/Medisys_Configurations/SIT2/Batch/appsettings.json">
			<tags>
				<value>SIT2_Copy_mbrDtl_Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="SIT3_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/SIT3/App/appsettings.json">
			<tags>
				<value>SIT3_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="SIT3_Copy_mbrDtl_Batch_appsettings_json" file="DeploymentFiles/Medisys_Configurations/SIT3/Batch/appsettings.json">
			<tags>
				<value>SIT3_Copy_mbrDtl_Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="UAT1_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/UAT1/App/appsettings.json">
			<tags>
				<value>UAT1_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="UAT1_Copy_mbrDtl_Batch_appsettings_json" file="DeploymentFiles/Medisys_Configurations/UAT1/Batch/appsettings.json">
			<tags>
				<value>UAT1_Copy_mbrDtl_Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="UAT2_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/UAT2/App/appsettings.json">
			<tags>
				<value>UAT2_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="UAT2_Copy_mbrDtl_Batch_appsettings_json" file="DeploymentFiles/Medisys_Configurations/UAT2/Batch/appsettings.json">
			<tags>
				<value>UAT2_Copy_mbrDtl_Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="Missouri_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/Missouri/App/appsettings.json">
			<tags>
				<value>Missouri_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="Missouri_Copy_mbrDtl_Batch_appsettings_json" file="DeploymentFiles/Medisys_Configurations/Missouri/Batch/appsettings.json">
			<tags>
				<value>Missouri_Copy_mbrDtl_Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="PERF_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/PERF/PERF/App/appsettings.json">
			<tags>
				<value>PERF_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="PERF_Copy_mbrDtl_Bath_appsettings_json" file="DeploymentFiles/Medisys_Configurations/PERF/PERF/Batch/appsettings.json">
			<tags>
				<value>PERF_Copy_mbrDtl_Batch_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>

		<file.File name="PERFRO_Copy_mbrDtl_appsettings_json" file="DeploymentFiles/Medisys_Configurations/PERF/PERFRO/App/appsettings.json">
			<tags>
				<value>PERFRO_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>

		<file.File name="PROD_Copy_mbrDtl_App_appsettings_json" file="DeploymentFiles/Medisys_Configurations/PROD/PROD/App/appsettings.json">
			<tags>
				<value>PROD_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
		<file.File name="PROD_Copy_mbrDtl_Batch347_appsettings_json" file="DeploymentFiles/Medisys_Configurations/PROD/PROD/Batch/VA10PWVISS347/appsettings.json">
			<tags>
				<value>PROD_Copy_mbrDtl_Batch347_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>

		<file.File name="PROD_Copy_mbrDtl_Batch348_appsettings_json" file="DeploymentFiles/Medisys_Configurations/PROD/PROD/Batch/VA10PWVISS348/appsettings.json">
			<tags>
				<value>PROD_Copy_mbrDtl_Batch348_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>

		<file.File name="PRODRO_Copy_mbrDtl_appsettings_json" file="DeploymentFiles/Medisys_Configurations/PROD/PRODRO/App/appsettings.json">
			<tags>
				<value>PRODRO_Copy_mbrDtl_appsettings_json</value>
			</tags>
			<targetPath>{{targetmbrDtlPath}}</targetPath>
			<targetFileName>appsettings.json</targetFileName>
			<checksum></checksum>
		</file.File>
	
		<cmd.Command name="Z002-mbrDtl_start_apppool">
			<commandLine>powershell `${001-Copy_mbrDtl_stop_start_app_pool.ps1} -applicationPoolName {{IIS_mbrDtl}} -Action {{Action_Application_Pool_Start}}</commandLine>
			<order>50</order>
			<dependencies>
				<ci ref="001-Copy_mbrDtl_stop_start_app_pool.ps1"/> 
			</dependencies>
			<undoOrder>49</undoOrder>
			<undoCommandLine></undoCommandLine>
			<undoDependencies/>
			<runUndoCommandOnUpgrade>true</runUndoCommandOnUpgrade>
			<tags>
				<value>DEV2</value>
				<value>DEV3</value>
				<value>SIT2</value>
				<value>SIT3</value>
				<value>UAT1</value>
				<value>UAT2</value>
				<value>PERF</value>
				<value>Missouri</value>
				<value>Trng</value>
				<value>PROD</value>
			</tags>
		</cmd.Command>
	</deployables>
	<applicationDependencies />
	<dependencyResolution>LATEST</dependencyResolution>
	<undeployDependencies>false</undeployDependencies>
	<templates />
	<boundTemplates />
</udm.DeploymentPackage>
"@
# Nlog.config file template
$NlogContent = @"
<?xml version="1.0" encoding="utf-8" ?>
<nlog xmlns="http://www.nlog-project.org/schemas/NLog.xsd"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
	<targets>
		<target name="jsonFile" xsi:type="File"
			  archiveNumbering="DateAndSequence"
			  archiveAboveSize="5000000"
			  fileName="E:\GMEWebLogs\$DefaultControlsName\Log-`${shortdate}.json">
			<layout xsi:type="JsonLayout">
				<attribute name="timestamp" layout="`${longdate}" />
				<attribute name="category" layout="`${level:upperCase=true}"/>
				<attribute name="message" layout="`${message}" />
				<attribute name="machine" layout="`${machinename}"/>
				<attribute name="appDomain" layout="`${appdomain}"/>
				<attribute name="processId" layout="`${processid}"/>
				<attribute name="processName" layout="`${processname}"/>
				<attribute name="threadId" layout="`${threadid}"/>
				<attribute name="threadName" layout="`${threadname}"/>
				<attribute name="callerId" layout="`${event-properties:item=callerId}"/>
				<attribute name="reqURL" layout="`${event-properties:item=reqURL}"/>
				<attribute name="requestId" layout="`${event-properties:item=requestId}"/>
				<attribute name="RequestInfo" layout="`${event-properties:item=RequestInfo}"/>
				<attribute name="Exception Type" layout="`${exception:format=Type}"/>
				<attribute name="Exception Message" layout="`${exception:format=Message}"/>
				<attribute name="StackTrace" layout="`${exception:format=StackTrace}"/>
				<attribute name="Additional Info" layout="`${exception:format=message}"/>
			</layout>
		</target>
		<target name="exceptionFile" xsi:type="File"
			archiveNumbering="DateAndSequence"
			archiveAboveSize="5000000"
			fileName="E:\GMEWebLogs\$DefaultControlsName\LogException-`${shortdate}.json">
			<layout xsi:type="JsonLayout">
				<attribute name="timestamp" layout="`${longdate}" />
				<attribute name="category" layout="`${level:upperCase=true}"/>
				<attribute name="message" layout="`${message}" />
				<attribute name="machine" layout="`${machinename}"/>
				<attribute name="appDomain" layout="`${appdomain}"/>
				<attribute name="processId" layout="`${processid}"/>
				<attribute name="processName" layout="`${processname}"/>
				<attribute name="threadId" layout="`${threadid}"/>
				<attribute name="threadName" layout="`${threadname}"/>
				<attribute name="callerId" layout="`${event-properties:item=callerId}"/>
				<attribute name="requestId" layout="`${event-properties:item=requestId}"/>
				<attribute name="RequestInfo" layout="`${event-properties:item=RequestInfo}"/>
				<attribute name="Exception Type" layout="`${exception:format=Type}"/>
				<attribute name="Exception Message" layout="`${exception:format=Message}"/>
				<attribute name="StackTrace" layout="`${exception:format=StackTrace}"/>
				<attribute name="Additional Info" layout="`${exception:format=message}"/>
			</layout>
		</target>
	</targets>
	<rules>
		<logger name="*" minlevel="Debug" writeTo="jsonFile" />
		<logger name="*"  minlevel="Warn" writeTo="exceptionFile"/>
	</rules>
</nlog>
"@
$Medisys_Configurations_env ="$workspacePath\Medisys_Configurations\DEV2\App
$workspacePath\Medisys_Configurations\DEV2\Batch
$workspacePath\Medisys_Configurations\DEV3\App
$workspacePath\Medisys_Configurations\DEV3\Batch
$workspacePath\Medisys_Configurations\Missouri\App
$workspacePath\Medisys_Configurations\Missouri\Batch
$workspacePath\Medisys_Configurations\PERF\PERF\App
$workspacePath\Medisys_Configurations\PERF\PERF\Batch
$workspacePath\Medisys_Configurations\PERF\PERFRO\App
$workspacePath\Medisys_Configurations\PROD\PROD\App
$workspacePath\Medisys_Configurations\PROD\PROD\Batch\VA10PWVISS1067
$workspacePath\Medisys_Configurations\PROD\PROD\Batch\VA10PWVISS347
$workspacePath\Medisys_Configurations\PROD\PROD\Batch\VA10PWVISS348
$workspacePath\Medisys_Configurations\PROD\PRODRO\App
$workspacePath\Medisys_Configurations\SIT2\App
$workspacePath\Medisys_Configurations\SIT2\Batch
$workspacePath\Medisys_Configurations\SIT3\App
$workspacePath\Medisys_Configurations\SIT3\Batch
$workspacePath\Medisys_Configurations\UAT1\App
$workspacePath\Medisys_Configurations\UAT1\Batch
$workspacePath\Medisys_Configurations\UAT2\App
$workspacePath\Medisys_Configurations\UAT2\Batch
$workspacePath\Medisys_Configurations\UAT3\App
$workspacePath\Medisys_Configurations\UAT3\Batch"

$readMeContent = @"
# Demoservice 

What is a README File? In simple words, we can describe a README file as a guide that gives users a detailed description of a project you have worked on. It can also be described as documentation with guidelines on how to use a project. Usually it will have instructions on how to install and run the project.

| S.No | Conflunce Link | Comment | 
| :---:   | :---: | :---: |
| 1 | [Automation & Innovation](https://confluence.elevancehealth.com/pages/viewpage.action?spaceKey=GME&title=Automation) | Visit the Confluence link to learn more about the new Medisys API Generation tool and other automation tools. The page also provides documentation for these tools. |


[Follow the instruction to edit the README.md File](https://confluence.elevancehealth.com/pages/viewpage.action?spaceKey=GME&title=Automation) 
"@

write-host "[3/10]=========================> Creating Project Folder Structure " -ForegroundColor Yellow

# Create the project folder structure
# Check the controller folder is exist or not
if(!(Test-Path -Path "$workspacePath\Controllers"))
{
   $null = New-Item -Path "$workspacePath\Controllers" -ItemType Directory
}
# Check the model folder is exist or not
if(!(Test-Path -Path "$workspacePath\Models"))
{
    $null = New-Item -Path "$workspacePath\Models" -ItemType Directory
    if(!(Test-Path -Path "$workspacePath\Models\Context"))
    {
        $null = New-Item -Path "$workspacePath\Models\Context" -ItemType Directory
    }
}
# Check the Business folder is exist or not
if(!(Test-Path -Path "$workspacePath\Business"))
{
    $null = New-Item -Path "$workspacePath\Business" -ItemType Directory
}
# Check the Repository folder is exist or not
if(!(Test-Path -Path "$workspacePath\Repositories"))
{
    $null = New-Item -Path "$workspacePath\Repositories" -ItemType Directory
}
# Check the Middlewares folder is exist or not
if(!(Test-Path -Path "$workspacePath\Middlewares"))
{
   $null = New-Item -Path "$workspacePath\Middlewares" -ItemType Directory
}
# Check the Handlers folder is exist or not
if(!(Test-Path -Path "$workspacePath\Handlers"))
{
   $null = New-Item -Path "$workspacePath\Handlers" -ItemType Directory
}
# Check the Common folder is exist or not
if(!(Test-Path -Path "$workspacePath\Common"))
{
   $null = New-Item -Path "$workspacePath\Common" -ItemType Directory
}
# Check the App_Start folder is exist or not
if(!(Test-Path -Path "$workspacePath\App_Start"))
{
   $null = New-Item -Path "$workspacePath\App_Start" -ItemType Directory
}
# Check the Interface folder is exist or not
if(!(Test-Path -Path "$workspacePath\Interfaces"))
{
   $null = New-Item -Path "$workspacePath\Interfaces" -ItemType Directory
}
# Check the Validators folder is exist or not
if(!(Test-Path -Path "$workspacePath\Validators"))
{
   $null = New-Item -Path "$workspacePath\Validators" -ItemType Directory
}
if(!(Test-Path -Path "$workspacePath\Medisys_Configurations"))
{
	$null = New-Item -Path "$workspacePath\Medisys_Configurations" -ItemType Directory
}

# Check the README.md file is exist or not
if(!(Test-Path -Path "$workspacePath\README.md"))
{
   $null = New-Item -Path "$workspacePath\README.md" -ItemType File
}

Write-Host "[4/10]=========================> Folder Structure Created Successfully" -ForegroundColor Yellow

$contentFromCsproj = Get-Content -Path $csprojName
$contentFromCsproj = $contentFromCsproj -replace '</Project>', '
  <ItemGroup>
    <Folder Include="Controllers\" />
    <Folder Include="Models\" />
    <Folder Include="Business\" />
    <Folder Include="Repositories\" />
    <Folder Include="Middlewares\" />
    <Folder Include="Handlers\" />
    <Folder Include="Common\" />
    <Folder Include="App_Start\" />
    <Folder Include="Interfaces\" />
    <Folder Include="Validators\" />
	<Folder Include="Medisys_Configurations\" />
  </ItemGroup>
</Project>'
Set-Content -Path $csprojName -Value $contentFromCsproj

# Create the template files
# Create Startup.cs file
if(!(Test-Path -Path "$workspacePath\Startup.cs"))
{
   $null = New-Item -Path "$workspacePath\Startup.cs" -ItemType File
}
# Create Program.cs file
if(!(Test-Path -Path "$workspacePath\Program.cs"))
{
   $null = New-Item -Path "$workspacePath\Program.cs" -ItemType File
}
# Create DependencyInjection.cs file
if(!(Test-Path -Path "$workspacePath\App_Start\DependencyInjectionConfig.csn"))
{
   $null = New-Item -Path "$workspacePath\App_Start\DependencyInjectionConfig.cs" -ItemType File
}
# Create Business processor file
if(!(Test-Path -Path "$workspacePath\Business\$($DefaultControlsName)RequestProcessor.cs"))
{
   $null = New-Item -Path "$workspacePath\Business\$($DefaultControlsName)RequestProcessor.cs" -ItemType File
} 
# Create Interface file
if(!(Test-Path -Path "$workspacePath\Interfaces\I$($DefaultControlsName)RequestProcessor.cs"))
{
   $null = New-Item -Path "$workspacePath\Interfaces\I$($DefaultControlsName)RequestProcessor.cs" -ItemType File
}
# Create Application Constants file
if(!(Test-Path -Path "$workspacePath\Common\ApplicationConstant.cs"))
{
   $null = New-Item -Path "$workspacePath\Common\ApplicationConstant.cs" -ItemType File
}
# Create StoredProcs json file
if(!(Test-Path -Path "$workspacePath\Common\StoredProcs.json"))
{
   $null = New-Item -Path "$workspacePath\Common\StoredProcs.json" -ItemType File
}
# Create StoredProcs cs file
if(!(Test-Path -Path "$workspacePath\Common\StoredProcs.cs"))
{
   $null = New-Item -Path "$workspacePath\Common\StoredProcs.cs" -ItemType File
}
# Create ExceptionHandler file
if(!(Test-Path -Path "$workspacePath\Handlers\ExceptionHandler.cs"))
{
   $null = New-Item -Path "$workspacePath\Handlers\ExceptionHandler.cs" -ItemType File
}
# Create Middleware file
if(!(Test-Path -Path "$workspacePath\Middlewares\RequestMiddleware.cs"))
{
   $null = New-Item -Path "$workspacePath\Middlewares\RequestMiddleware.cs" -ItemType File
}
# Create DBContext file
if(!(Test-Path -Path "$workspacePath\Models\Context\DBContext.cs"))
{
   $null = New-Item -Path "$workspacePath\Models\Context\DBContext.cs" -ItemType File
}
# Create Default Error file
if(!(Test-Path -Path "$workspacePath\Common\ErrorDetails.cs"))
{
   $null = New-Item -Path "$workspacePath\Common\ErrorDetails.cs" -ItemType File
}
# Create Common Utility file
if(!(Test-Path -Path "$workspacePath\Common\Utility.cs"))
{
   $null = New-Item -Path "$workspacePath\Common\Utility.cs" -ItemType File
}
# Create Request model file 
if(!(Test-Path -Path "$workspacePath\Models\$($DefaultControlsName)Request.cs"))
{
   $null = New-Item -Path "$workspacePath\Models\$($DefaultControlsName)Request.cs" -ItemType File
}
# Create Response model file
if(!(Test-Path -Path "$workspacePath\Models\$($DefaultControlsName)Response.cs"))
{
   $null = New-Item -Path "$workspacePath\Models\$($DefaultControlsName)Response.cs" -ItemType File
}
# Create Base Validator file
if(!(Test-Path -Path "$workspacePath\Validators\BaseValidator.cs"))
{
   $null = New-Item -Path "$workspacePath\Validators\BaseValidator.cs" -ItemType File
}
# Create Repository file
if(!(Test-Path -Path "$workspacePath\Repositories\$($DefaultControlsName)Repository.cs"))
{
   $null = New-Item -Path "$workspacePath\Repositories\$($DefaultControlsName)Repository.cs" -ItemType File
} 
# Remove Invalid file
Get-ChildItem -Path "$workspacePath\Controllers\" -Recurse -Filter "*.cs" | Remove-Item -Force
Remove-Item -path "$workspacePath\WeatherForecast.cs" -Force

# Create AntiForgeryController file
if(!(Test-Path -Path "$workspacePath\Controllers\AntiForgeryController.cs"))
{
   $null = New-Item -Path "$workspacePath\Controllers\AntiForgeryController.cs" -ItemType File
}
# Create  AppSettings.json
if(!(Test-Path -Path "$workspacePath\appsettings.json"))
{
	New-Item -Path "$workspacePath\appsettings.json" -ItemType File
} 
# Create Medisys_Configurations sub folder 
if(!(Test-Path -Path "$workspacePath\Medisys_Configurations\Common"))
{
	$null = New-Item -Path "$workspacePath\Medisys_Configurations\Common" -ItemType Directory
}
# Copy all the json files from Common folder to Medisys_Configurations sub folder 
Get-ChildItem -Path "$workspacePath\Common" -Recurse -Filter "*.json" | Copy-Item -Destination "$workspacePath\Medisys_Configurations\Common" -Force

# Create Nlog.config file
if(!(Test-Path -Path "$workspacePath\nlog.config"))
{
   $null = New-Item -Path "$workspacePath\nlog.config" -ItemType File
}

# Overwrite the content of the files
Set-Content -Path "$workspacePath\Startup.cs" -Value $StartupContent
Set-Content -Path "$workspacePath\Program.cs" -Value $ProgramContent
Set-Content -Path "$workspacePath\App_Start\DependencyInjectionConfig.cs" -Value $DependencyInjectionConfigContent
Set-Content -Path "$workspacePath\Business\$($DefaultControlsName)RequestProcessor.cs" -Value $DefaultBusinessProcessorContent
Set-Content -Path "$workspacePath\Interfaces\I$($DefaultControlsName)RequestProcessor.cs" -Value $DefaultBusinessProcessorInterfaceContent
Set-Content -Path "$workspacePath\Common\ApplicationConstant.cs" -Value $ApplicationConstantContent
Set-Content -Path "$workspacePath\Common\StoredProcs.json" -Value $StoredProcsJsonContent
Set-Content -Path "$workspacePath\Common\StoredProcs.cs" -Value $StoredProcsContent
Set-Content -Path "$workspacePath\Handlers\ExceptionHandler.cs" -Value $ExceptionHandlerContent
Set-Content -Path "$workspacePath\Middlewares\RequestMiddleware.cs" -Value $RequestMiddlewareContent
Set-Content -Path "$workspacePath\Models\Context\DBContext.cs" -Value $DBContextContent
Set-Content -Path "$workspacePath\Common\ErrorDetails.cs" -Value $CommonErrorDetailsContent
Set-Content -Path "$workspacePath\Common\Utility.cs" -Value $CommonUtilityContent
Set-Content -Path "$workspacePath\Models\$($DefaultControlsName)Request.cs" -Value $ModelRequestContent
Set-Content -Path "$workspacePath\Models\$($DefaultControlsName)Response.cs" -Value $ModelResponseContent
Set-Content -Path "$workspacePath\Validators\BaseValidator.cs" -Value $BaseValidatorContent
Set-Content -Path "$workspacePath\Repositories\$($DefaultControlsName)Repository.cs" -Value $RepositorieContent
Set-Content -Path "$workspacePath\Controllers\AntiForgeryController.cs" -Value $AddAntiforgeryContent
Set-Content -Path "$workspacePath\nlog.config" -Value $NlogContent
Set-Content -Path "$workspacePath\appsettings.json" -Value $AppSettingsContent
Set-Content -Path "$workspacePath\README.md" -Value $readMeContent
# Copy nlog.config file to Medisys_Configurations sub folder
Copy-Item -Path "$workspacePath\nlog.config" -Destination "$workspacePath\Medisys_Configurations\Common" -Force

# Create the Medisys_Configurations sub folder for each environment
$EnvLevle = $EnvLevle | ConvertFrom-Json
$Medisys_Configurations_env -split "`n" | ForEach-Object {
	
	$dir = $_.Trim()
	if($dir -ne "")
	{
		if(!(Test-Path -Path $dir))
		{
			$null = New-Item -Path $dir -ItemType Directory
		}
		Copy-Item -Path $appsettingJsonPath -Destination $dir -Force
		$envSpecificPath = "$dir\appsettings.json"
		$envSpecificappsettingJsonObj = Get-Content -Path $envSpecificPath -Raw | ConvertFrom-Json 

		$EnvLevle | ForEach-Object {
			$_.PSObject.Properties | ForEach-Object {
				$var = $($_.Value | ConvertTo-Json) 
        		$var = $var | ConvertFrom-Json
				if($dir -Like "*$($_.Name)*")
				{
					$envSpecificappsettingJsonObj.ConnectionStrings.DefaultConnection = $var.ConnectionString
					$envSpecificappsettingJsonObj.Services.GatewayService = $var.GatewayService
					$envSpecificappsettingJsonObj.Services.GatewayDirectory = $var.GatewayDirectory
				}
				
			}
		}
		$FinalJson = $envSpecificappsettingJsonObj | ConvertTo-Json -Depth 100
		Set-Content -Path $envSpecificPath -Value $FinalJson
    }
}
# Read-Host :"Check the build status before"
Write-Host "[5/10]=========================> Folder Structure Added to the Project File" -ForegroundColor Yellow
$BuildStatus = & dotnet build 
# Read-Host :"Check the build status after"
$isBuildSuccess = $false
if($BuildStatus -like "*Build succeeded*")
{
	write-host "[6/10]=========================> Project Build complete" -ForegroundColor Yellow
	$isBuildSuccess = $true
}
else
{
	write-host "[6/10]=========================> Project Build Failed `n Please validate the code file or template code and build and publish it manually." -ForegroundColor Red
	$isBuildSuccess = $false
}
# write-host "[6/10]=========================> Project Build complete" -ForegroundColor Yellow
Set-Location -Path $currentDir
write-host "[7/10]=========================> appsettings.json Created Successfully" -ForegroundColor Yellow
write-host "[8/10]=========================> appsettings.json Created Successfully for all Environments" -ForegroundColor Yellow	

if(!(Test-Path -Path "$apiPath\$apiRootFolder") -and ($apiName -ne $apiRootFolder)  ){
    Rename-Item -Path $workspacePath -NewName $apiRootFolder
    $workspacePath = "$apiPath\$apiRootFolder" 
}else{
	if($isRename){
		Write-Host "[x] Project already exists with the same name. Project created with the name $apiName. Please rename the project manually." -ForegroundColor Red
	}
}


write-host "[9/10]=========================> Project Created Successfully" -ForegroundColor Yellow
$YesArray = @("Y","YES")
$NoArray = @("N","NO")
$PushToGit = Read-Host "Do you want to push the project to Bitbucket? (Y/N)"
while($PushToGit -notin $YesArray -and $PushToGit -notin $NoArray){
	$PushToGit = Read-Host "Do you want to push the project to Bitbucket? (Y/N)"
}
if($YesArray -contains $PushToGit.ToUpper()){
	if($isBuildSuccess -eq $false){
		write-host "[10/10]=========================> Project Build Complete Successfully" -ForegroundColor Yellow
		Write-Host "Project Created Successfully" -ForegroundColor Green	
		Write-Host "[X] Project Build Failed. Cannot push the project to Git" -ForegroundColor Red
		Set-Location -Path $currentDir 
		Write-Host "Project Path : $workspacePath" -ForegroundColor Green
		exit
	}
    $GitPath = Read-Host "Enter the Git Repository URL"
	# $GitPathRegex = "https:\/\/[A-Z0-9]+\/[a-z]+\/[a-z-]+\.git" 
	# while($GitPath -notmatch $GitPathRegex){
	#	Write-Host "Invalid Git Repository URL" -ForegroundColor Red
	#	$GitPath = Read-Host "Enter the Git Repository URL"
	# }
	while($GitPath -eq ""){
		Write-Host "Git Repository URL is required" -ForegroundColor Red
		$GitPath = Read-Host "Enter the Git Repository URL"
	}
	$GitCommitMessage = Read-Host "Enter the Git Commit Message"
	if($GitCommitMessage -eq ""){
		write-host "Inital DevOps Code Checkin - API Generator" -ForegroundColor Green
		$GitCommitMessage = "Inital DevOps Code Checkin - API Generator"
	}
	Set-Location -Path $workspacePath
    if(!(Test-Path -Path "$workspacePath\.gitignore"))
	{
		$null = New-Item -Path "$workspacePath\.gitignore" -ItemType File
	}
	if(!(Test-Path -Path "$workspacePath\build.properties"))
	{
		$null = New-Item -Path "$workspacePath\build.properties" -ItemType File
	}
	if(!(Test-Path -Path "$workspacePath\deployit-manifest.xml"))
	{
		$null = New-Item -Path "$workspacePath\deployit-manifest.xml" -ItemType File
	}
	Set-Content -Path "$workspacePath\.gitignore" -Value $gitIgnoreContent
	Set-Content -Path "$workspacePath\build.properties" -Value $buildPropertyontent
	Set-Content -Path "$workspacePath\deployit-manifest.xml" -Value $deployManifestContent

    $dust = git init 2>&1 #| write-host
	$dust = git add --all 2>&1 #| write-host
	$dust = git commit -m "$GitCommitMessage" 2>&1 #| write-host
	$dust = git remote add origin $GitPath 2>&1 #| write-host
	$dust = git branch -M master 2>&1 #| write-host
	$dust = git push -u origin HEAD:master 2>&1 #| write-host
	# $null = $result
    write-host "[10/10]=========================> Project Build Complete Successfully" -ForegroundColor Yellow
	Write-Host "Project Created Successfully" -ForegroundColor Green	
	Write-Host "Project Pushed to Git Successfully" -ForegroundColor Green
}elseif($NoArray -contains $PushToGit.ToUpper()){
    write-host "[10/10]=========================> Project Build Complete Successfully" -ForegroundColor Yellow
	Write-Host "Project Created Successfully" -ForegroundColor Green	
}
Set-Location -Path $currentDir 
Write-Host "Project Path : $workspacePath" -ForegroundColor Green

} catch {
    Write-Host "[X] Error: $_" -ForegroundColor Red
}

Clear-History
