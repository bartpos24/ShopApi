namespace ShopApi.Models.Database
{
    public class Unit
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Code { get; set; }

        public virtual ICollection<Product> Products { get; set; }
    }
}
