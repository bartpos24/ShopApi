using System.ComponentModel.DataAnnotations.Schema;

namespace ShopApi.Models.Database
{
    [Table("Units")]
    public class ProductUnit
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Code { get; set; }
    }
}
