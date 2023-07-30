namespace Project21API_Db.Models
{
    public interface IContact
    {
        int ID { get; set; }
        string Surname { get; set; }
        string Name { get; set; }
        string FatherName { get; set; }
        string TelephoneNumber { get; set; }
        string ResidenceAdress { get; set; }
        string Description { get; set; }
    }
}
