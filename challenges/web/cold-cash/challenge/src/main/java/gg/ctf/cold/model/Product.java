package gg.ctf.cold.model;

public class Product {
    private String name;
    private int price;
    private String description;
    private int stock;

    public Product(String name, int price, String description) {
        this.name = name;
        this.price = price;
        this.description = description;
        this.stock = 10;
    }

    public String getName() {
        return name;
    }

    public int getPrice() {
        return price;
    }

    public String getDescription() {
        return description;
    }

    public int getStock() {
        return stock;
    }

    public void setStock(int stock) {
        this.stock = stock;
    }

    public boolean hasStock(int quantity) {
        return stock >= quantity;
    }

    public void reduceStock(int quantity) {
        if (hasStock(quantity)) {
            this.stock -= quantity;
        }
    }
} 