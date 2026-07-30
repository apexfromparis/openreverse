#pragma once
namespace kyv { class Application; namespace panels {
class ConsolePanel {
public:
    void Render(Application& app);
private:
    bool showDebug_ = true;
    bool showInfo_ = true;
    bool showWarning_ = true;
    bool showError_ = true;
};
}} // namespace
