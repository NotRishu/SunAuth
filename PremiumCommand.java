package com.rishuxd.plugin;

import com.rishuxd.plugin.commands.LoginCommand;
import com.rishuxd.plugin.commands.PremiumCommand;
import com.rishuxd.plugin.commands.RegisterCommand;
import com.rishuxd.plugin.listeners.AuthListener;
import com.rishuxd.plugin.utils.PlayerDataManager;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.Objects;

/**
 * AuthPlugin - Hybrid login system for Paper 26.1.2
 *
 * Supports both premium (online-mode) and cracked players.
 * Passwords are stored as AES-256(SHA-256(plaintext)) in players.yml.
 *
 * @author rishuxd
 * @version 1.0.0
 */
public final class AuthPlugin extends JavaPlugin {

    private static AuthPlugin instance;
    private PlayerDataManager playerDataManager;
    private AuthListener authListener;

    @Override
    public void onEnable() {
        instance = this;

        saveDefaultConfig();
        saveResource("players.yml", false);

        playerDataManager = new PlayerDataManager(this);

        authListener = new AuthListener(this);
        getServer().getPluginManager().registerEvents(authListener, this);

        Objects.requireNonNull(getCommand("register")).setExecutor(new RegisterCommand(this));
        Objects.requireNonNull(getCommand("login")).setExecutor(new LoginCommand(this));
        Objects.requireNonNull(getCommand("premium")).setExecutor(new PremiumCommand(this));

        getLogger().info("AuthPlugin v" + getDescription().getVersion() + " enabled!");
        getLogger().info("Password storage: SHA-256 + AES-256 encrypted.");
    }

    @Override
    public void onDisable() {
        if (playerDataManager != null) playerDataManager.saveData();
        getLogger().info("AuthPlugin disabled. All data saved.");
    }

    public static AuthPlugin getInstance() { return instance; }
    public PlayerDataManager getPlayerDataManager() { return playerDataManager; }
    public AuthListener getAuthListener() { return authListener; }
}
