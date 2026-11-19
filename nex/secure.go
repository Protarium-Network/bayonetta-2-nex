package nex

import (
	"fmt"
	"os"
	"strconv"

	nexgo "github.com/PretendoNetwork/nex-go/v2"
	"github.com/PretendoNetwork/nex-go/v2/types"
	commonNattraversal "github.com/PretendoNetwork/nex-protocols-common-go/v2/nat-traversal"
	commonSecure "github.com/PretendoNetwork/nex-protocols-common-go/v2/secure-connection"
	nattraversal "github.com/PretendoNetwork/nex-protocols-go/v2/nat-traversal"
	secure "github.com/PretendoNetwork/nex-protocols-go/v2/secure-connection"

	commonMatchmaking "github.com/PretendoNetwork/nex-protocols-common-go/v2/match-making"
	commonMatchmakingext "github.com/PretendoNetwork/nex-protocols-common-go/v2/match-making-ext"
	commonMatchmakeextension "github.com/PretendoNetwork/nex-protocols-common-go/v2/matchmake-extension"
	matchmaking "github.com/PretendoNetwork/nex-protocols-go/v2/match-making"
	matchmakingext "github.com/PretendoNetwork/nex-protocols-go/v2/match-making-ext"
	matchmakeextension "github.com/PretendoNetwork/nex-protocols-go/v2/matchmake-extension"

	matchmakingtypes "github.com/PretendoNetwork/nex-protocols-go/v2/match-making/types"

	"github.com/Protarium-Network/bayonetta-2-nex/globals"
)

var SecureServer *nexgo.PRUDPServer
var SecureEndpoint *nexgo.PRUDPEndPoint

func StartSecureServer() {
	SecureServer = nexgo.NewPRUDPServer()

	SecureServer.PRUDPV1Settings.LegacyConnectionSignature = globals.LegacyConnectionSignature

	SecureServer.LibraryVersions.SetDefault(nexgo.NewLibraryVersion(globals.NEXMajor, globals.NEXMinor, globals.NEXPatch))
	SecureServer.AccessKey = globals.AccessKey

	SecureEndpoint = nexgo.NewPRUDPEndPoint(1)
	SecureEndpoint.IsSecureEndPoint = true
	SecureEndpoint.ServerAccount = globals.SecureServerAccount
	SecureEndpoint.AccountDetailsByPID = globals.AccountDetailsByPID
	SecureEndpoint.AccountDetailsByUsername = globals.AccountDetailsByUsername

	SecureServer.BindPRUDPEndPoint(SecureEndpoint)
	globals.SecureEndpoint = SecureEndpoint

	SecureEndpoint.OnData(func(packet nexgo.PacketInterface) {
		request := packet.RMCMessage()
		if request == nil {
			return
		}

		fmt.Printf("[BNT Secure] PID=%d protocol=%s (0x%02X) method=0x%02X\n",
			uint64(packet.Sender().PID()),
			globals.GetProtocolNameByID(request.ProtocolID),
			request.ProtocolID,
			request.MethodID)
	})

	SecureEndpoint.OnConnectionEnded(func(connection *nexgo.PRUDPConnection) {
		fmt.Printf("[NAN Secure] PID=%d disconnected\n", uint64(connection.PID()))
	})

	SecureEndpoint.OnError(func(err *nexgo.Error) {
		globals.Logger.Errorf("[NAN Secure] %v", err)
	})

	secureProtocol := secure.NewProtocol()
	SecureEndpoint.RegisterServiceProtocol(secureProtocol)

	secureCommon := commonSecure.NewCommonProtocol(secureProtocol)
	secureCommon.EnableInsecureRegister()

	globals.MatchmakingManager.GetUserFriendPIDs = globals.GetUserFriendPIDs

	natTraversalProtocol := nattraversal.NewProtocol()
	globals.SecureEndpoint.RegisterServiceProtocol(natTraversalProtocol)
	commonNattraversal.NewCommonProtocol(natTraversalProtocol)

	matchMakingProtocol := matchmaking.NewProtocol()
	globals.SecureEndpoint.RegisterServiceProtocol(matchMakingProtocol)
	commonMatchmaking.NewCommonProtocol(matchMakingProtocol).SetManager(globals.MatchmakingManager)

	matchMakingExtProtocol := matchmakingext.NewProtocol()
	globals.SecureEndpoint.RegisterServiceProtocol(matchMakingExtProtocol)
	commonMatchmakingext.NewCommonProtocol(matchMakingExtProtocol).SetManager(globals.MatchmakingManager)

	matchmakeExtensionProtocol := matchmakeextension.NewProtocol()
	globals.SecureEndpoint.RegisterServiceProtocol(matchmakeExtensionProtocol)
	commonMatchmakeExtensionProtocol := commonMatchmakeextension.NewCommonProtocol(matchmakeExtensionProtocol)
	commonMatchmakeExtensionProtocol.SetManager(globals.MatchmakingManager)

	commonMatchmakeExtensionProtocol.CleanupMatchmakeSessionSearchCriterias = func(searchCriterias types.List[matchmakingtypes.MatchmakeSessionSearchCriteria]) {
		for i := range searchCriterias {
			// * Give this attribute a value to prevent FindMatchmakeSessionsBySearchCriteria from throwing an error
			searchCriterias[i].Attribs[1] = "0"
		}
	}

	port, err := strconv.Atoi(os.Getenv("PN_BNT_SECURE_PORT"))
	if err != nil || port < 1 || port > 65535 {
		port = 60000
	}

	globals.Logger.Successf("[NAN] Secure server listening on UDP %d", port)
	SecureServer.Listen(port)
}
