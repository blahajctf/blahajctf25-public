#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <queue>
#include <map>
#include <limits>
#include <numeric> 
#include <cstdio>
#include <csignal>
#include <unistd.h>
#include <fstream>

const int NUM_NODES = 67;
const int NUM_EDGES = 67;
const int PATH_LEN = 6;
const char* FLAG = "blahaj{D0_Y0U_l1K3_9R4Ph_7h30RY?_1_l1k3_9R4ph_7H30ry!}";

using Edge = std::pair<int, int>;
using Graph = std::vector<std::vector<Edge>>;

struct PathResult {
    std::vector<int> nodes;
    int total_weight = -1; 
};

std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);

void handle_timeout(int signum) {
    printf("\nSorry, time's up!\n");
    _exit(1);
}

int get_random_from_dev(int min, int max) {
    if (!urandom.is_open() || min > max) {
        fprintf(stderr, "Fatal Error in RNG. Exiting.\n");
        exit(1);
    }
    unsigned int random_value;
    urandom.read(reinterpret_cast<char*>(&random_value), sizeof(random_value));
    if (urandom.fail()) {
        fprintf(stderr, "Fatal Error: seriouslyed to read from /dev/urandom.\n");
        exit(1);
    }
    return min + (random_value % (static_cast<unsigned int>(max) - min + 1));
}


Graph create_dense_graph_with_long_path(int total_nodes, int path_len, int total_edges, int& out_start_node, int& out_end_node) {
    Graph adj(total_nodes);

    std::vector<int> available_nodes(total_nodes);
    std::iota(available_nodes.begin(), available_nodes.end(), 0); 

    std::vector<int> scaffold_nodes;
    scaffold_nodes.reserve(path_len);

    for (int i = 0; i < path_len; ++i) {
        int rand_idx = get_random_from_dev(0, available_nodes.size() - 1);
        
        int chosen_node = available_nodes[rand_idx];
        scaffold_nodes.push_back(chosen_node);
        
        std::swap(available_nodes[rand_idx], available_nodes.back());
        available_nodes.pop_back();
    }

    out_start_node = scaffold_nodes.front();
    out_end_node = scaffold_nodes.back();

    int current_edges = 0;
    for (size_t i = 0; i < scaffold_nodes.size() - 1; ++i) {
        int u = scaffold_nodes[i];
        int v = scaffold_nodes[i + 1];
        int weight = get_random_from_dev(1, 10);
        adj[u].push_back({v, weight});
        adj[v].push_back({u, weight});
        current_edges++;
    }

    while (current_edges < total_edges) {
        int u = get_random_from_dev(0, total_nodes - 1);
        int v = get_random_from_dev(0, total_nodes - 1);

        if (u == v || adj[u].size() >= 4 || adj[v].size() >= 4) continue;
        if ((u == out_start_node && v == out_end_node) || (u == out_end_node && v == out_start_node)) continue;

        bool edge_exists = false;
        for (const auto& edge : adj[u]) {
            if (edge.first == v) {
                edge_exists = true;
                break;
            }
        }
        if (edge_exists) continue;

        int weight = get_random_from_dev(1, 10);
        adj[u].push_back({v, weight});
        adj[v].push_back({u, weight});
        current_edges++;
    }
    return adj;
}

PathResult dijkstra(const Graph& graph, int start_node, int end_node) {
    std::vector<int> distances(graph.size(), std::numeric_limits<int>::max());
    std::vector<int> predecessors(graph.size(), -1);
    std::priority_queue<std::pair<int, int>, std::vector<std::pair<int, int>>, std::greater<std::pair<int, int>>> pq;

    distances[start_node] = 0;
    pq.push({0, start_node});

    while (!pq.empty()) {
        int u = pq.top().second;
        pq.pop();
        if (u == end_node) break;
        for (const auto& edge : graph[u]) {
            int v = edge.first;
            int weight = edge.second;
            if (distances[u] != std::numeric_limits<int>::max() && distances[u] + weight < distances[v]) {
                distances[v] = distances[u] + weight;
                predecessors[v] = u;
                pq.push({distances[v], v});
            }
        }
    }

    PathResult result;
    if (distances[end_node] == std::numeric_limits<int>::max()) return result; // No path

    result.total_weight = distances[end_node];
    int current_node = end_node;
    while (current_node != -1) {
        result.nodes.push_back(current_node);
        current_node = predecessors[current_node];
    }
    std::reverse(result.nodes.begin(), result.nodes.end());
    
    if (result.nodes.empty() || result.nodes[0] != start_node) return {};
    
    return result;
}

std::string convert_funtime_path_to_udlr(const Graph& graph, const std::vector<int>& funtime_path) {
    if (funtime_path.size() < 2) return "";
    std::string udlr_path;
    const std::map<int, char> direction_map = {{0, 'U'}, {1, 'D'}, {2, 'L'}, {3, 'R'}};

    for (size_t i = 0; i < funtime_path.size() - 1; ++i) {
        int current_node = funtime_path[i];
        int next_node = funtime_path[i + 1];

        std::vector<Edge> neighbors = graph[current_node];
        std::sort(neighbors.begin(), neighbors.end(), [](const Edge& a, const Edge& b) {
            return a.first < b.first;
        });

        for (size_t j = 0; j < neighbors.size(); ++j) {
            if (neighbors[j].first == next_node) {
                udlr_path += direction_map.at(j);
                break;
            }
        }
    }
    return udlr_path;
}


std::string generate_challenge_source_code(const Graph& graph, int start_node, int end_node, int shortest_path_weight) {
    std::stringstream ss;
    ss << "import sys\n\n";
    ss << "sys.setrecursionlimit(" << (graph.size() * 4) << ")\n\n";
    ss << "def get_flag():\n";
    ss << "    try:\n";
    ss << "        with open('flag.txt', 'r') as f: print(f.read())\n";
    ss << "    except FileNotFoundError: print('flag.txt not found.')\n\n";
    ss << "def aw_man():\n    print('huh? where? where?')\n\n";
    ss << "def seriously():\n    print('you ever think about that?')\n\n";

    for (size_t node = 0; node < graph.size(); ++node) {
        ss << "def funtime_" << node << "(p, w):\n";
        if (node == static_cast<size_t>(end_node)) {
            ss << "    if w == " << shortest_path_weight << ":\n";
            ss << "        print('good job vro')\n";
            ss << "        get_flag()\n";
            ss << "    else:\n";
            ss << "        print('think a little harder')\n\n";
            continue;
        }
        ss << "    if not p: aw_man(); return\n";
        ss << "    d = p[0]; r = p[1:]\n";

        std::vector<Edge> neighbors = graph[node];
        std::sort(neighbors.begin(), neighbors.end(), [](const Edge& a, const Edge& b) {
            return a.first < b.first;
        });

        const char directions[] = {'U', 'D', 'L', 'R'};
        bool first_if = true;
        for (size_t i = 0; i < neighbors.size(); ++i) {
            ss << "    " << (first_if ? "if" : "elif") << " d == '" << directions[i] << "':\n";
            ss << "        funtime_" << neighbors[i].first << "(r, w + " << neighbors[i].second << ")\n";
            first_if = false;
        }
        if (!first_if) ss << "    else: seriously()\n\n";
        else ss << "    seriously()\n\n";
    }
    ss << "def main():\n";
    ss << "    gimme = input('shimmy shimmy ya: ')\n";
    ss << "    funtime_" << start_node << "(gimme, 0)\n\n";
    ss << "if __name__ == '__main__':\n    main()\n";
    return ss.str();
}

void validate_user_path(const Graph& graph, int start_node, int end_node, int shortest_path_weight, const std::string& user_path) {
    int current_node = start_node;
    int current_weight = 0;
    for (char direction : user_path) {
        std::vector<Edge> neighbors = graph[current_node];
        std::sort(neighbors.begin(), neighbors.end(), [](const Edge& a, const Edge& b) { return a.first < b.first; });

        int move_index = -1;
        if (direction == 'U') move_index = 0; else if (direction == 'D') move_index = 1;
        else if (direction == 'L') move_index = 2; else if (direction == 'R') move_index = 3;

        if (move_index == -1 || static_cast<size_t>(move_index) >= neighbors.size()) {
            printf("you ever think about that?\n"); return;
        }
        
        current_weight += neighbors[move_index].second;
        current_node = neighbors[move_index].first;
    }

    if (current_node == end_node) {
        if (current_weight == shortest_path_weight) {
            printf("good job vro\n");
            printf("Here is your flag: %s\n", FLAG);
        } else {
            printf("think a little harder\n");
        }
    } else {
        printf("huh? where? where?\n");
    }
}

int main() {
    if (!urandom.is_open()) {
        fprintf(stderr, "Fatal Error: Could not open /dev/urandom. Exiting.\n");
        return 1;
    }

    int start_node, end_node;
    Graph graph;
    PathResult result;

    do {    
        graph = create_dense_graph_with_long_path(NUM_NODES, PATH_LEN, NUM_EDGES, start_node, end_node);
        result = dijkstra(graph, start_node, end_node);
    } while (result.total_weight == -1 || result.nodes.size() < PATH_LEN);

    
    std::string solution_path_udlr = convert_funtime_path_to_udlr(graph, result.nodes);

    std::string challenge_source = generate_challenge_source_code(graph, start_node, end_node, result.total_weight);
    printf("\n%s play my game %s\n", std::string(25, '-').c_str(), std::string(25, '-').c_str());
    printf("%s", challenge_source.c_str());
    printf("%s play my game %s\n", std::string(25, '-').c_str(), std::string(25, '-').c_str());
    fflush(stdout); 
    
    signal(SIGALRM, handle_timeout);
    alarm(5);
    printf("You have 5 seconds to submit your answer...\n\n");
    fflush(stdout);
    
    printf("Running the script...\n\n");
    fflush(stdout); 
    
    printf("shimmy shimmy ya: ");
    fflush(stdout); 
    
    char user_answer_buffer[2048]; 
    if (scanf("%2047s", user_answer_buffer) != 1) {
        // Handle potential scanf error or EOF
        return 1;
    }
    alarm(0);

    validate_user_path(graph, start_node, end_node, result.total_weight, user_answer_buffer);

    urandom.close();
    return 0;
}