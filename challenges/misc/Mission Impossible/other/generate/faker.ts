import { faker } from "@faker-js/faker/locale/en_US";
import fs from "fs";

function generateEmployee() {
  const firstName = faker.person.firstName();
  const lastName = faker.person.lastName();
  const email = faker.internet.email({
    firstName: firstName,
    lastName: lastName,
  });

  const phoneNumber = faker.phone.number({
    style: "international",
  });

  const address = faker.location.streetAddress({ useFullAddress: true });

  const department = faker.helpers.arrayElement([
    "Human Resources",
    "Finance",
    "Engineering",
    "Marketing",
    "Sales",
    "Customer Support",
    "IT",
    "Legal",
    "Operations",
    "Research and Development",
    "Product Management",
    "Design",
  ]);

  const salary = faker.number.int({ min: 30000, max: 150000 });

  const hireDate = faker.date.past({ years: 10 }).toISOString().split("T")[0];

  return {
    firstName,
    lastName,
    email,
    phoneNumber,
    department,
    address,
    salary,
    hireDate,
  };
}

let employees: any[] = [];
let departments: string[] = [];
for (let i = 0; i < 1000; i++) {
  const employee = generateEmployee();
  employees.push(employee);
}

fs.writeFileSync("employees.json", JSON.stringify(employees, null, 2), "utf-8");
