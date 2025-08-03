package gg.ctf.cold.controller;

import gg.ctf.cold.model.CartItem;
import gg.ctf.cold.model.Product;
import gg.ctf.cold.model.ShoppingCart;
import gg.ctf.cold.model.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.annotation.SessionScope;

import jakarta.servlet.http.HttpSession;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.io.File;
import java.io.IOException;


@Controller
@RequestMapping("/")
@SessionScope
public class ShopController {
    private File flagFile = new File("/flag.txt");

    private List<Product> availableProducts = new ArrayList<>(Arrays.asList(
        new Product("flag", 1000000, "you should buy one of these (if you can afford it)"),
        new Product("Sahara Breeze", 50, "cool relief for desert conditions"),
        new Product("Aurès Avalanche", 45, "solid block from the mountain heights"),
        new Product("Pellet Beldi", 16, "compact, efficient traditional dry ice"),
        new Product("Casbah Crystals", 25, "refined blocks with a clean finish"),
        new Product("Kabyle Chill", 30, "balanced ice block with lasting cold")
    ));
    
    @GetMapping
    public String shop(HttpSession session, Model model) throws IOException {
        // Initialize user if not exists
        User user = (User) session.getAttribute("user");
        if (user == null) {
            user = new User("guest", false);
            session.setAttribute("user", user);
        }

        // Initialize cart if not exists
        ShoppingCart cart = (ShoppingCart) session.getAttribute("cart");
        if (cart == null) {
            cart = new ShoppingCart();
            session.setAttribute("cart", cart);
        }
        
        model.addAttribute("cart", cart);
        model.addAttribute("products", availableProducts);
        model.addAttribute("user", user);
        model.addAttribute("flag", flagFile.exists() ? new String(java.nio.file.Files.readAllBytes(flagFile.toPath())) : "Flag not found");
        return "shop";
    }

    @PostMapping("/add")
    public String addToCart(@RequestParam String productName, 
                          @RequestParam int quantity, 
                          HttpSession session) {
        ShoppingCart cart = (ShoppingCart) session.getAttribute("cart");
        Product product = availableProducts.stream()
            .filter(p -> p.getName().equals(productName))
            .findFirst()
            .orElse(null);
            
        if (product != null && product.hasStock(quantity)) {
            cart.addItem(new CartItem(product.getName(), product.getPrice(), Math.abs(quantity)));
        }
        return "redirect:/";
    }

    @PostMapping("/remove/{index}")
    public String removeFromCart(@PathVariable int index, HttpSession session) {
        ShoppingCart cart = (ShoppingCart) session.getAttribute("cart");
        cart.removeItem(index);
        return "redirect:/";
    }

    @PostMapping("/purchase")
    public String purchase(HttpSession session) {
        ShoppingCart cart = (ShoppingCart) session.getAttribute("cart");
        if (cart.canAfford()) {
            boolean allInStock = cart.getItems().stream().allMatch(item -> {
                Product product = availableProducts.stream()
                    .filter(p -> p.getName().equals(item.getName()))
                    .findFirst()
                    .orElse(null);
                return product != null && product.hasStock(item.getQuantity());
            });

            if (allInStock) {
                cart.getItems().forEach(item -> {
                    Product product = availableProducts.stream()
                        .filter(p -> p.getName().equals(item.getName()))
                        .findFirst()
                        .orElse(null);
                    if (product != null) {
                        product.reduceStock(item.getQuantity());
                    }
                });
                cart.purchase();
            }
        }
        return "redirect:/";
    }

    @PostMapping("/admin/add-product")
    public String addProduct(@RequestParam String name,
                           @RequestParam int price,
                           @RequestParam String description,
                           HttpSession session) {
        User user = (User) session.getAttribute("user");
        if ((user.admin = true) && user != null && name != "flag") {
            availableProducts.add(new Product(name, price, description));
        }
        return "redirect:/";
    }

    @PostMapping("/apply-coupon")
    public String applyCoupon(@RequestParam String couponCode, HttpSession session) {
        ShoppingCart cart = (ShoppingCart) session.getAttribute("cart");
        if (cart != null) {
            cart.setCouponCode(couponCode);
        }
        return "redirect:/";
    }

    @PostMapping("/remove-coupon")
    public String removeCoupon(HttpSession session) {
        ShoppingCart cart = (ShoppingCart) session.getAttribute("cart");
        if (cart != null) {
            cart.setCouponCode(null);
        }
        return "redirect:/";
    }
} 