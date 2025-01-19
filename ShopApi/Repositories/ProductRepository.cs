using Dapper;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Data.SqlClient;
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
                table.Rows.Add(
                    product.Id, 
                    product.Barcode, 
                    product.Name.Length > 500 ? product.Name.Substring(0, 500) : product.Name, 
                    product.Brand.Length > 500 ? product.Brand.Substring(0, 500) : product.Brand, 
                    product.Capacity.Length > 500 ? product.Capacity.Substring(0, 500) : product.Capacity, 
                    product.Label.Length > 500 ? product.Label.Substring(0, 500) : product.Label
                    );
            }
            var parameters = new DynamicParameters();
            parameters.Add("@Info", dbType: DbType.AnsiString, direction: ParameterDirection.InputOutput, size: 500);
            parameters.Add("@Products", table.AsTableValuedParameter("InitProductTableType"));
            var result = await ExecuteStoredProcedure("InitializeProductFromCSV", parameters, transaction: transaction);

            return parameters.Get<string>("@Info");
        }
    }
}
