using Dapper;
using Microsoft.Data.SqlClient;
using System.Data;

namespace ShopApi.Repositories
{
    public abstract class ShopDapperRepository : DapperRepository
    {
        private Lazy<IDbConnection> LazyConnection { get; }
        protected override IDbConnection Connection => LazyConnection.Value;
        public ShopDapperRepository(IConfiguration configuration) : base(configuration) 
        {
            LazyConnection = new Lazy<IDbConnection>(() => new SqlConnection(Configuration.GetConnectionString("ShopDatabase")));
        }
        protected ValueTask<int> ExecuteStoredProcedure(string procedureName, object? param = null, int? commandTimeout = null, IDbTransaction? transaction = null, CancellationToken cancellationToken = default)
        {
            var connection = TransactionConnection(transaction);
            var timeout = commandTimeout ?? Configuration.GetValue<int>("Connection:StoredProcedureTimeoutInS");
            return new ValueTask<int>(connection.ExecuteAsync(new CommandDefinition(commandText: procedureName, parameters: param, transaction: transaction, commandTimeout: timeout, commandType: CommandType.StoredProcedure, cancellationToken: cancellationToken)));
        }
        protected IDbConnection TransactionConnection(IDbTransaction? transaction) => transaction?.Connection ?? Connection;
    }
}
