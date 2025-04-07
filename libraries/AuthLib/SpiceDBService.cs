using Authzed.Api.V1;
using Grpc.Net.Client;
using Grpc.Core;

public class SpiceDBService
{
    private readonly PermissionsService.PermissionsServiceClient _client;
    private readonly string _token;

    public SpiceDBService(string endpoint, string token)
    {
        _token = token;

        var channel = GrpcChannel.ForAddress(endpoint, new GrpcChannelOptions
        {
            HttpHandler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            }
        });

        _client = new PermissionsService.PermissionsServiceClient(channel);
    }

    public async Task<bool> CheckPermissionAsync(string user, string resource, string permission)
    {
        try
        {

            var metadata = new Metadata
            {
                { "authorization", $"bearer {_token}" }
            };

            var request = new CheckPermissionRequest
            {
                Resource = new ObjectReference
                {
                    ObjectType = "document",
                    ObjectId = resource
                },
                Permission = permission,
                Subject = new SubjectReference
                {
                    Object = new ObjectReference
                    {
                        ObjectType = "user",
                        ObjectId = user
                    }
                }
            };

            var callOptions = new CallOptions(headers: metadata);

            var response = await _client.CheckPermissionAsync(request, callOptions);

            return response.Permissionship == CheckPermissionResponse.Types.Permissionship.HasPermission;
        }
        catch (RpcException ex)
        {
            throw;
        }
    }
}