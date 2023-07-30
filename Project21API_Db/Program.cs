using Microsoft.AspNetCore;


namespace Project21API_Db
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)  
                .UseStartup<Startup>();
    }
}
