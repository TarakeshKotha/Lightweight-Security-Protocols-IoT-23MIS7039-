#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/applications-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"

using namespace ns3;

// ---------------- SECURITY ----------------
std::map<uint32_t, double> trust;
std::set<uint32_t> malicious = {2, 5};

uint32_t controlPackets = 0;
double compOverhead = 0;

bool Authenticate(uint32_t id)
{
    controlPackets++;
    compOverhead += 0.001;
    return true; // DO NOT block traffic
}

bool IDS(uint32_t id)
{
    controlPackets++;
    compOverhead += 0.002;
    return malicious.count(id);
}

void UpdateTrust(uint32_t id, bool attack)
{
    if (attack)
        trust[id] -= 0.05;
    else
        trust[id] += 0.02;

    trust[id] = std::max(0.0, std::min(1.0, trust[id]));
}

// ---------------- MAIN ----------------
int main()
{
    uint32_t nIoT = 10;
    uint32_t gatewayIndex = nIoT;
    uint32_t totalNodes = nIoT + 1;

    NodeContainer nodes;
    nodes.Create(totalNodes);

    // ---------------- WIFI (UNCHANGED) ----------------
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);

    YansWifiPhyHelper phy;
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    // ---------------- MOBILITY ----------------
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);

    // ---------------- INTERNET ----------------
    InternetStackHelper stack;
    stack.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer interfaces = address.Assign(devices);

    // ---------------- SERVER ----------------
    uint16_t port = 9;
    UdpServerHelper server(port);

    ApplicationContainer serverApp = server.Install(nodes.Get(gatewayIndex));
    serverApp.Start(Seconds(0.0));
    serverApp.Stop(Seconds(30.0));

    // ---------------- TRUST INIT ----------------
    for (uint32_t i = 0; i < nIoT; i++)
        trust[i] = 0.5;

    uint32_t totalPackets = 0;

    // ---------------- CLIENTS (UNCHANGED TRAFFIC) ----------------
    for (uint32_t i = 0; i < nIoT; i++)
    {
        Authenticate(i);
        bool attack = IDS(i);
        UpdateTrust(i, attack);

        UdpClientHelper client(interfaces.GetAddress(gatewayIndex), port);

        client.SetAttribute("MaxPackets", UintegerValue(180));
        client.SetAttribute("Interval", TimeValue(Seconds(0.3)));
        client.SetAttribute("PacketSize", UintegerValue(256));

        ApplicationContainer app = client.Install(nodes.Get(i));
        app.Start(Seconds(1.0 + i * 0.2));
        app.Stop(Seconds(30.0));

        totalPackets += 180;
    }

    // ---------------- FLOW MONITOR ----------------
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    // ---------------- NETANIM (CLEAN CIRCULAR VIEW) ----------------
    AnimationInterface anim("paper_secure.xml");
    anim.EnablePacketMetadata(true);

    // Gateway center
    anim.SetConstantPosition(nodes.Get(gatewayIndex), 50, 50);

    // Circular layout
    double radius = 25;

    for (uint32_t i = 0; i < nIoT; i++)
    {
        double angle = 2 * M_PI * i / nIoT;
        double x = 50 + radius * cos(angle);
        double y = 50 + radius * sin(angle);

        anim.SetConstantPosition(nodes.Get(i), x, y);
    }

    // Node colors & labels
    for (uint32_t i = 0; i < totalNodes; i++)
    {
        if (i == gatewayIndex)
        {
            anim.UpdateNodeDescription(nodes.Get(i), "Gateway");
            anim.UpdateNodeColor(nodes.Get(i), 0, 255, 0);
            anim.UpdateNodeSize(i, 3.0, 3.0);
        }
        else if (malicious.count(i))
        {
            anim.UpdateNodeDescription(nodes.Get(i), "Malicious");
            anim.UpdateNodeColor(nodes.Get(i), 255, 0, 0);
            anim.UpdateNodeSize(i, 2.5, 2.5);
        }
        else
        {
            anim.UpdateNodeDescription(nodes.Get(i), "IoT-" + std::to_string(i));
            anim.UpdateNodeColor(nodes.Get(i), 0, 0, 255);
            anim.UpdateNodeSize(i, 2.5, 2.5);
        }
    }

    Simulator::Stop(Seconds(30.0));
    Simulator::Run();

    // ---------------- RESULTS ----------------
    monitor->CheckForLostPackets();

    double tx = 0, rx = 0, delaySum = 0, jitterSum = 0;

    for (auto &f : monitor->GetFlowStats())
    {
        tx += f.second.txPackets;
        rx += f.second.rxPackets;
        delaySum += f.second.delaySum.GetSeconds();
        jitterSum += f.second.jitterSum.GetSeconds();
    }

    double pdr = (tx > 0) ? rx / tx : 0;
    double delay = (rx > 0) ? delaySum / rx : 0;
    double jitter = (rx > 0) ? jitterSum / rx : 0;
    double throughput = (rx * 256 * 8) / (30 * 1000);
    double loss = tx - rx;

    double commOverhead = (totalPackets > 0) ?
                          (double)controlPackets / totalPackets : 0;

    std::cout << "\n===== FINAL RESULTS =====\n";
    std::cout << "Packets Sent = " << tx << std::endl;
    std::cout << "Packets Received = " << rx << std::endl;
    std::cout << "PDR = " << pdr << std::endl;
    std::cout << "End-to-End Delay = " << delay << std::endl;
    std::cout << "Average Jitter = " << jitter << std::endl;
    std::cout << "Throughput = " << throughput << " Kbps\n";
    std::cout << "Packet Loss = " << loss << std::endl;
    std::cout << "Communication Overhead = " << commOverhead << std::endl;
    std::cout << "Computational Overhead = " << compOverhead << std::endl;

    Simulator::Destroy();
    return 0;
}
