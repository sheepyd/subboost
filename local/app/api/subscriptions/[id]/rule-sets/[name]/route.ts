import { handleRuleSetRequest } from "@local/lib/ios-client-route";

type RouteContext = {
  params: Promise<{ id: string; name: string }>;
};

export async function GET(request: Request, { params }: RouteContext) {
  const { id: token, name } = await params;
  return handleRuleSetRequest(request, token, name);
}
