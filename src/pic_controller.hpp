#pragma once

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>

/**
 * @brief PicController manages PIC state with JSON persistence
 *
 * This class provides state management for PIC (Provisioning Interface
 * Controller) with automatic persistence to /etc/provisioning/picctrl.json
 */
class PicController
{
  public:
    /**
     * @brief Construct a new PicController object
     * Loads state from JSON file if it exists
     */
    PicController()
    {
        loadState();
    }

    /**
     * @brief Set the PIC state
     * @param value The new state value
     * @return true if state was successfully saved, false otherwise
     */
    bool setState(bool value)
    {
        state = value;
        return saveState();
    }

    /**
     * @brief Get the current PIC state
     * @return bool The current state
     */
    bool getState() const
    {
        return state;
    }

  private:
    static constexpr const char* jsonFilePath =
        "/etc/provisioning/picctrl.json";
    bool state{false};

    /**
     * @brief Load state from JSON file
     * If file doesn't exist or is invalid, state remains false
     */
    void loadState()
    {
        try
        {
            if (std::filesystem::exists(jsonFilePath))
            {
                std::ifstream file(jsonFilePath);
                if (file.is_open())
                {
                    nlohmann::json j;
                    file >> j;
                    if (j.contains("state") && j["state"].is_boolean())
                    {
                        state = j["state"].get<bool>();
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            // If loading fails, keep default state (false)
            state = false;
        }
    }

    /**
     * @brief Save current state to JSON file
     * Creates directory if it doesn't exist
     * @return true if save was successful, false otherwise
     */
    bool saveState()
    {
        try
        {
            // Ensure directory exists
            std::filesystem::path filePath(jsonFilePath);
            std::filesystem::path dirPath = filePath.parent_path();

            if (!std::filesystem::exists(dirPath))
            {
                std::filesystem::create_directories(dirPath);
            }

            // Write JSON file
            nlohmann::json j;
            j["state"] = state;

            std::ofstream file(jsonFilePath);
            if (file.is_open())
            {
                file << j.dump(4); // Pretty print with 4 space indent
                file.close();
                return true;
            }
            return false;
        }
        catch (const std::exception& e)
        {
            return false;
        }
    }
};
