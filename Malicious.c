#include "main.h"
#include "AODV.h"
#include "List.h"

#define BLACKHOLE_NODE_ID 4  // Change to your malicious node's ID

int fn_NetSim_AODV_IsBlackholeNode(NetSim_EVENTDETAILS* pstruEventDetails)
{
    return pstruEventDetails->nDeviceId == BLACKHOLE_NODE_ID;
}

int fn_NetSim_AODV_BlackholeHandleRREQ(NetSim_EVENTDETAILS* pstruEventDetails)
{
    if (!fn_NetSim_AODV_IsBlackholeNode(pstruEventDetails)) return 0;

    AODV_RREQ* rreq = (AODV_RREQ*)pstruEventDetails->pPacket->pstruNetworkData->Packet_RoutingProtocol;

    // Create a fake RREP with high sequence number
    NetSim_PACKET* rrepPacket = fn_NetSim_AODV_CreateRREP(
        pstruEventDetails->nDeviceId,
        rreq->OriginatorIPAddress,
        rreq->DestinationIPAddress,
        rreq->DestinationSequenceNumber + 100,  // Fake high seq number
        1                                       // Minimum hop count
    );

    // Schedule the RREP event
    NetSim_EVENTDETAILS pevent;
    memcpy(&pevent, pstruEventDetails, sizeof(NetSim_EVENTDETAILS));
    pevent.nEventType = NETWORK_OUT_EVENT;
    pevent.pPacket = rrepPacket;
    pevent.dEventTime += 1.0;
    fnpAddEvent(&pevent);

    // Drop the RREQ
    fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
    return 1;
}

int fn_NetSim_AODV_BlackholeHandleData(NetSim_EVENTDETAILS* pstruEventDetails)
{
    if (!fn_NetSim_AODV_IsBlackholeNode(pstruEventDetails)) return 0;

    // Drop all received data packets
    if (pstruEventDetails->pPacket->nPacketType == PacketType_App)
    {
        AODV_DEV_VAR(pstruEventDetails->nDeviceId)->aodvMetrics.packetDropped++;
        fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
        return 1;
    }

    return 0;
}
