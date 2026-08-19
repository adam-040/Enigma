// Heavy C++ sample: templates, STL containers, inheritance, virtual
// dispatch, exceptions, RTTI, namespaces, lambdas, smart pointers.
#include <algorithm>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace inventory {

enum class ItemKind : unsigned char { Weapon = 1, Armor, Potion, Scroll };

struct ItemStats {
    unsigned int weight : 10;
    unsigned int quality : 4;
    unsigned int cursed : 1;
    unsigned int reserved : 17;
    double baseValue;
    long long serial;
};

class Item {
public:
    Item(std::string name, ItemKind kind, ItemStats stats)
        : name_(std::move(name)), kind_(kind), stats_(stats) {}
    virtual ~Item() = default;
    virtual double appraisedValue() const { return stats_.baseValue * qualityFactor(); }
    virtual std::string describe() const;
    const std::string& name() const { return name_; }
    ItemKind kind() const { return kind_; }

protected:
    virtual double qualityFactor() const { return 0.5 + stats_.quality / 16.0; }

private:
    std::string name_;
    ItemKind kind_;
    ItemStats stats_;
};

class EnchantedItem : public Item {
public:
    EnchantedItem(std::string name, ItemKind kind, ItemStats stats, int enchantLevel)
        : Item(std::move(name), kind, stats), enchantLevel_(enchantLevel) {}
    double appraisedValue() const override {
        return Item::appraisedValue() * (1.0 + 0.25 * enchantLevel_);
    }
    std::string describe() const override;

private:
    double qualityFactor() const override { return 0.7 + statsBoost(); }
    double statsBoost() const { return enchantLevel_ * 0.02; }
    int enchantLevel_;
};

std::string Item::describe() const {
    std::ostringstream os;
    os << name_ << " (kind " << static_cast<int>(kind_) << ", value "
       << appraisedValue() << ")";
    return os.str();
}

std::string EnchantedItem::describe() const {
    return "[enchanted x" + std::to_string(enchantLevel_) + "] " + Item::describe();
}

template <typename T, typename Compare = std::less<T>>
class StatRegistry {
public:
    void insert(T value) {
        auto it = std::lower_bound(values_.begin(), values_.end(), value, Compare{});
        values_.insert(it, std::move(value));
    }
    size_t size() const { return values_.size(); }
    const T& median() const { return values_[values_.size() / 2]; }
    T sum() const {
        T total{};
        for (const auto& v : values_) total = total + v;
        return total;
    }

private:
    std::vector<T> values_;
};

template <typename K, typename V>
class LruCache {
public:
    explicit LruCache(size_t capacity) : capacity_(capacity) {}
    std::optional<V> get(const K& key) {
        auto it = map_.find(key);
        if (it == map_.end()) return std::nullopt;
        touch(it);
        return it->second.value;
    }
    void put(const K& key, V value) {
        auto it = map_.find(key);
        if (it != map_.end()) {
            it->second.value = std::move(value);
            touch(it);
            return;
        }
        if (map_.size() >= capacity_) evict();
        map_[key] = {std::move(value), ++clock_};
    }

private:
    struct Entry {
        V value;
        uint64_t stamp;
    };
    void touch(typename std::unordered_map<K, Entry>::iterator& it) {
        it->second.stamp = ++clock_;
    }
    void evict() {
        auto oldest = std::min_element(map_.begin(), map_.end(),
                                       [](const auto& a, const auto& b) {
                                           return a.second.stamp < b.second.stamp;
                                       });
        if (oldest != map_.end()) map_.erase(oldest);
    }
    size_t capacity_;
    uint64_t clock_ = 0;
    std::unordered_map<K, Entry> map_;
};

}  // namespace inventory

static long long fib(int n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2);
}

static double harmonic(int n) {
    double acc = 0.0;
    for (int i = 1; i <= n; ++i) acc += 1.0 / i;
    return acc;
}

int main() {
    using namespace inventory;

    std::vector<std::unique_ptr<Item>> bag;
    bag.push_back(std::make_unique<Item>("Iron Sword", ItemKind::Weapon,
                                         ItemStats{120, 9, 0, 0, 42.5, 1001LL}));
    bag.push_back(std::make_unique<EnchantedItem>("Oak Staff", ItemKind::Weapon,
                                                  ItemStats{80, 12, 0, 0, 30.0, 1002LL}, 3));
    bag.push_back(std::make_unique<EnchantedItem>("Chain Mail", ItemKind::Armor,
                                                  ItemStats{2000, 6, 1, 0, 88.25, 1003LL}, 1));
    bag.push_back(std::make_unique<Item>("Healing Draught", ItemKind::Potion,
                                         ItemStats{15, 3, 0, 0, 9.99, 1004LL}));

    double total = 0.0;
    for (const auto& item : bag) {
        std::cout << item->describe() << "\n";
        total += item->appraisedValue();
    }

    StatRegistry<int> reg;
    for (int i = 0; i < 33; ++i) reg.insert(static_cast<int>(fib(i % 17) % 100));
    std::cout << "registry size=" << reg.size() << " median=" << reg.median()
              << " sum=" << reg.sum() << "\n";

    LruCache<std::string, double> cache(4);
    for (int i = 0; i < 10; ++i) {
        cache.put("k" + std::to_string(i % 6), harmonic(i + 1));
    }
    for (int i = 0; i < 6; ++i) {
        auto v = cache.get("k" + std::to_string(i));
        std::cout << "cache k" << i << " = " << (v ? *v : -1.0) << "\n";
    }

    std::map<std::string, std::vector<int>> grouped;
    for (int i = 0; i < 40; ++i) {
        grouped[std::to_string(i % 5)].push_back(i * i);
    }
    for (const auto& [key, vals] : grouped) {
        std::cout << "group " << key << ":";
        for (int v : vals) std::cout << ' ' << v;
        std::cout << '\n';
    }

    try {
        if (bag.empty()) throw std::logic_error("empty bag");
        throw std::runtime_error("demo exception");
    } catch (const std::logic_error& e) {
        std::cerr << "logic: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "exception: " << e.what() << "\n";
    }

    std::mutex m;
    std::lock_guard<std::mutex> lock(m);
    std::cout << "total value " << total << " fib(20)=" << fib(20) << "\n";
    return 0;
}
