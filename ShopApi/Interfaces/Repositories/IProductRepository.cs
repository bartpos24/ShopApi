using System.Data;

namespace ShopApi.Interfaces.Repositories
{
    public interface IProductRepository
    {
        public ValueTask<string> InitProductFromCSV(string csvFilePath, IDbTransaction? transaction = null);
    }
}
