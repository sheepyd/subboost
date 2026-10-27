import { handleIosClientConfigRequest } from "@local/lib/ios-client-route";

type RouteContext = {
  params: Promise<{ id: string }>;
};

export async function GET(request: Request, { params }: RouteContext) {
  const { id: token } = await params;
  return handleIosClientConfigRequest(request, token, "shadowrocket");
}
