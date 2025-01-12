using Dapper;
using ShopApi.Extensions;
using ShopApi.Interfaces.Repositories;
using ShopApi.Models.Database;
using System.Data;

namespace ShopApi.Repositories
{
    public class ProductRepository : ShopDapperRepository, IProductRepository
    {
        public ProductRepository(IConfiguration configuration) : base(configuration) { }

        public async ValueTask<string> InitProductFromCSV(string csvFilePath, IDbTransaction? transaction = null)
        {
            List<InitProduct> listOfProduct = FileReaderExtensions.ReadProductFromCSV(csvFilePath);

            var table = new DataTable();
            table.Columns.Add("Id", typeof(int));
            table.Columns.Add("Barcode", typeof(string));
            table.Columns.Add("Name", typeof(string));
            table.Columns.Add("Brand", typeof(string));
            table.Columns.Add("Capacity", typeof(string));
            table.Columns.Add("Label", typeof(string));

            foreach(var product in listOfProduct)
            {
                table.Rows.Add(product.Id, product.Barcode, product.Name, product.Brand, product.Capacity, product.Label);
            }
            var parameters = new DynamicParameters();
            parameters.Add("@Info", dbType: DbType.AnsiString, direction: ParameterDirection.InputOutput, size: 500);
            parameters.AddDynamicParams(table);
            var result = await ExecuteStoredProcedure("InitializeProductFromCSV", parameters, transaction: transaction);

            return parameters.Get<string>("@Info");
        }
    }
}
