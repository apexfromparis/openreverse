#pragma once

#include <string>
#include <vector>

namespace kyv::ai {

struct ReverseSkill
{
    std::string id;
    std::string title;
    std::string description;
    std::string systemPrompt;
};

class ReverseSkillRegistry
{
public:
    ReverseSkillRegistry();

    const std::vector<ReverseSkill>& All() const { return skills_; }
    const ReverseSkill* Find(const std::string& id) const;

private:
    std::vector<ReverseSkill> skills_;
};

} // namespace kyv::ai
