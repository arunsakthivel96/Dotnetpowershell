param (
    [string]$name,
    [string]$path= (Get-Location).Path,
    [string]$folder = ""
)
try {
# mandatory parameters
$apiName = $name

if($apiName -eq $null -or $apiName -eq "") {
    do {
        write-host "[x] API name is mandatory either Provide the API Name or use [Ctrl + C] to exit and run the script with .\WebAPIGenerator.ps1 -name <Web.API.Name>" -ForegroundColor Red
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
$null = dotnet add $csprojName package NLog.Extensions.Logging 
$null = dotnet add $csprojName package Microsoft.Data.SqlClient 
$null = dotnet add $csprojName package Dapper 
write-host "[2/10]=========================> Solution created Successfully" -ForegroundColor Yellow

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
		public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseDeveloperExceptionPage();
				app.UseSwagger();
				app.UseSwaggerUI();
			}
			else
			{
				app.ConfigureExceptionHandler(Configuration);
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
	"StoredProcs": {
		"StoredProc": [
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
        public List<StoredProcConfig> StoredProc { get; set; }
    }
	/// <summary>
	/// Represents a configuration for a stored procedure.
	/// </summary>
	public class StoredProcConfig
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
		public static void ConfigureExceptionHandler(this IApplicationBuilder app, IConfiguration configuration)
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
		/// Indicates whether logging is enabled or not.
		/// </summary>
		private string isLoggingEnabled = ApplicationConstant.N;
		/// <summary>
		/// Initializes a new instance of the <see cref="RequestMiddleware"/> class.
		/// </summary>
		/// <param name="next">The request delegate.</param>
		/// <param name="logger">The logger.</param>
		/// <param name="configuration">The configuration.</param>
		public RequestMiddleware(RequestDelegate next, IConfiguration configuration)
		{
			_next = next;
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
		
		private readonly IAntiforgery _antiforgery;
		public AntiForgeryController(IAntiforgery antiforgery)
		{
			_antiforgery = antiforgery;
			
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
			
			try
			{
				var token = _antiforgery.GetAndStoreTokens(HttpContext);
				var response =  JsonSerializer.Serialize(token.RequestToken);
				return Content(response);
			}
			catch (Exception ex)
			{
				
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
    "DefaultConnection": "Data Source=sqldev2.us.ad.wellpoint.com\\SQL01,10001;Initial Catalog=demodb;TrustServerCertificate=true;Trusted_Connection=Yes;Integrated Security=True;"

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
    "GatewayDirectory": "/InternalAPIGateway"
  },
  "Config": {
    "SMTPServer": "smtprelay1.aici.com",
    "FromMail": "servermail@server.com",
    "ToMail": "arunsakthivel96@server.com"
  },
  "IsLoggingEnabled": "Y"
}
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
			  fileName="E:\WebLogs\$DefaultControlsName\Log-`${shortdate}.json">
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
			fileName="E:\WebLogs\$DefaultControlsName\LogException-`${shortdate}.json">
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

$SalesCrm_Configurations_env ="$workspacePath\SalesCrm_Configurations\DEV2\App
$workspacePath\SalesCrm_Configurations\DEV2\Batch
$workspacePath\SalesCrm_Configurations\DEV3\App
$workspacePath\SalesCrm_Configurations\DEV3\Batch
$workspacePath\SalesCrm_Configurations\Missouri\App
$workspacePath\SalesCrm_Configurations\Missouri\Batch
$workspacePath\SalesCrm_Configurations\PERF\PERF\App
$workspacePath\SalesCrm_Configurations\PERF\PERF\Batch
$workspacePath\SalesCrm_Configurations\PERF\PERFRO\App
$workspacePath\SalesCrm_Configurations\PROD\PROD\App
$workspacePath\SalesCrm_Configurations\PROD\PROD\Batch\
$workspacePath\SalesCrm_Configurations\PROD\PRODRO\App
$workspacePath\SalesCrm_Configurations\SIT2\App
$workspacePath\SalesCrm_Configurations\SIT2\Batch
$workspacePath\SalesCrm_Configurations\SIT3\App
$workspacePath\SalesCrm_Configurations\SIT3\Batch
$workspacePath\SalesCrm_Configurations\UAT1\App
$workspacePath\SalesCrm_Configurations\UAT1\Batch
$workspacePath\SalesCrm_Configurations\UAT2\App
$workspacePath\SalesCrm_Configurations\UAT2\Batch
$workspacePath\SalesCrm_Configurations\UAT3\App
$workspacePath\SalesCrm_Configurations\UAT3\Batch"


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
# SalesCrm_Configurations_env
if(!(Test-Path -Path "$workspacePath\SalesCrm_Configurations"))
{
	$null = New-Item -Path "$workspacePath\SalesCrm_Configurations" -ItemType Directory
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
	<Folder Include="SalesCrm_Configurations\" />
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
if(!(Test-Path -Path "$workspacePath\App_Start\DependencyInjectionConfig.cs"))
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

# Create SalesCrm_Configurations sub folder 
if(!(Test-Path -Path "$workspacePath\SalesCrm_Configurations\Common"))
{
	$null = New-Item -Path "$workspacePath\SalesCrm_Configurations\Common" -ItemType Directory
}
# Copy all the json files from Common folder to SalesCrm_Configurations sub folder 
Get-ChildItem -Path "$workspacePath\Common" -Recurse -Filter "*.json" | Copy-Item -Destination "$workspacePath\SalesCrm_Configurations\Common" -Force

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

# Copy nlog.config file to SalesCrm_Configurations sub folder
Copy-Item -Path "$workspacePath\nlog.config" -Destination "$workspacePath\SalesCrm_Configurations\Common" -Force

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
write-host "[10/10]=========================> Project Build Complete Successfully" -ForegroundColor Yellow
Write-Host "Project Created Successfully" -ForegroundColor Green	
Set-Location -Path $currentDir 
Write-Host "Project Path : $workspacePath" -ForegroundColor Green


}
catch {
    Write-Host "[X] Error: $_" -ForegroundColor Red
}
