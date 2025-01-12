using System.Data;

namespace ShopApi.Repositories
{
    public abstract class DapperRepository
    {
        protected abstract IDbConnection Connection { get; }
        protected IConfiguration Configuration { get; }
        public DapperRepository(IConfiguration configuration) => Configuration = configuration;
    }
}
