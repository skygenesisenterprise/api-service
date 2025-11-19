"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import {
  Play,
  Copy,
  Download,
  Code,
  Terminal,
  FileText,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Clock,
  Zap,
  Globe,
  Plus,
  Trash2,
  ChevronDown,
} from "lucide-react";
import { mockEndpoints } from "@/data/mockEndpoints";

const methodConfig = {
  GET: { color: "bg-green-100 text-green-700", label: "GET" },
  POST: { color: "bg-blue-100 text-blue-700", label: "POST" },
  PUT: { color: "bg-yellow-100 text-yellow-700", label: "PUT" },
  DELETE: { color: "bg-red-100 text-red-700", label: "DELETE" },
  PATCH: { color: "bg-purple-100 text-purple-700", label: "PATCH" },
  HEAD: { color: "bg-gray-100 text-gray-700", label: "HEAD" },
  OPTIONS: { color: "bg-indigo-100 text-indigo-700", label: "OPTIONS" },
};

interface RequestResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: any;
  time: number;
}

export default function ApiExplorerPage() {
  const [selectedEndpoint, setSelectedEndpoint] = useState(mockEndpoints[0]);
  const [method, setMethod] = useState("GET");
  const [url, setUrl] = useState("/api/v1/projects");
  const [headers, setHeaders] = useState([
    { key: "Content-Type", value: "application/json" },
    { key: "Authorization", value: "Bearer your-api-key" },
  ]);
  const [queryParams, setQueryParams] = useState([
    { key: "page", value: "1" },
    { key: "limit", value: "10" },
  ]);
  const [body, setBody] = useState(JSON.stringify({
    name: "Example Project",
    description: "This is a test project",
  }, null, 2));
  const [response, setResponse] = useState<RequestResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const addHeader = () => {
    setHeaders([...headers, { key: "", value: "" }]);
  };

  const removeHeader = (index: number) => {
    setHeaders(headers.filter((_, i) => i !== index));
  };

  const updateHeader = (index: number, field: "key" | "value", value: string) => {
    const newHeaders = [...headers];
    newHeaders[index][field] = value;
    setHeaders(newHeaders);
  };

  const addQueryParam = () => {
    setQueryParams([...queryParams, { key: "", value: "" }]);
  };

  const removeQueryParam = (index: number) => {
    setQueryParams(queryParams.filter((_, i) => i !== index));
  };

  const updateQueryParam = (index: number, field: "key" | "value", value: string) => {
    const newParams = [...queryParams];
    newParams[index][field] = value;
    setQueryParams(newParams);
  };

  const sendRequest = async () => {
    setIsLoading(true);
    
    // Simulate API call
    setTimeout(() => {
      const mockResponse: RequestResponse = {
        status: method === "POST" ? 201 : 200,
        statusText: method === "POST" ? "Created" : "OK",
        headers: {
          "content-type": "application/json",
          "x-request-id": "req_123456789",
          "x-ratelimit-remaining": "999",
        },
        body: method === "GET" ? {
          data: [
            {
              id: "1",
              name: "E-commerce Platform",
              description: "Production e-commerce platform",
              status: "active",
              createdAt: "2024-01-15T10:00:00Z",
            },
            {
              id: "2",
              name: "Mobile App Backend",
              description: "Backend services for mobile applications",
              status: "active",
              createdAt: "2024-02-20T14:30:00Z",
            },
          ],
          pagination: {
            page: 1,
            limit: 10,
            total: 2,
            totalPages: 1,
          },
        } : {
          id: "new_project_123",
          name: "Example Project",
          description: "This is a test project",
          status: "active",
          createdAt: new Date().toISOString(),
        },
        time: Math.random() * 500 + 100,
      };
      
      setResponse(mockResponse);
      setIsLoading(false);
    }, 1500);
  };

  const generateCurl = () => {
    const headersStr = headers
      .filter(h => h.key && h.value)
      .map(h => `-H "${h.key}: ${h.value}"`)
      .join(" ");
    
    const paramsStr = queryParams
      .filter(p => p.key && p.value)
      .map(p => `${p.key}=${p.value}`)
      .join("&");
    
    const urlWithParams = paramsStr ? `${url}?${paramsStr}` : url;
    const bodyStr = body ? `-d '${body}'` : "";
    
    return `curl -X ${method} ${headersStr} ${bodyStr} ${urlWithParams}`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
      },
    },
  };

  const cardVariants = {
    hidden: { opacity: 0, y: 20 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        duration: 0.3,
      },
    },
  };

  return (
    <div className="min-h-full bg-gray-50 p-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="mb-8"
      >
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div>
            <h1 className="text-3xl font-bold text-gray-900">API Explorer</h1>
            <p className="text-gray-600 mt-1">
              Test and explore your API endpoints interactively
            </p>
          </div>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Sidebar - Endpoint List */}
        <motion.div
          variants={cardVariants}
          initial="hidden"
          animate="visible"
          className="lg:col-span-1"
        >
          <Card className="h-full">
            <CardHeader>
              <CardTitle className="text-lg">Endpoints</CardTitle>
              <CardDescription>Select an endpoint to test</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="space-y-1 max-h-96 overflow-y-auto">
                {mockEndpoints.map((endpoint) => {
                  const methodStyle = methodConfig[endpoint.method];
                  return (
                    <button
                      key={endpoint.id}
                      onClick={() => {
                        setSelectedEndpoint(endpoint);
                        setMethod(endpoint.method);
                        setUrl(endpoint.route);
                      }}
                      className={`w-full text-left p-3 hover:bg-gray-50 border-b transition-colors ${
                        selectedEndpoint.id === endpoint.id ? "bg-blue-50 border-l-4 border-l-blue-500" : ""
                      }`}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Badge className={methodStyle.color}>
                          {methodStyle.label}
                        </Badge>
                        <span className="text-xs text-gray-500">{endpoint.service}</span>
                      </div>
                      <div className="text-sm font-medium text-gray-900 truncate">
                        {endpoint.route}
                      </div>
                      <div className="text-xs text-gray-500 truncate">
                        {endpoint.description}
                      </div>
                    </button>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        {/* Main Content - Request Builder */}
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          className="lg:col-span-3 space-y-6"
        >
          {/* Request Configuration */}
          <Card>
            <CardHeader>
              <CardTitle>Request Configuration</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Method and URL */}
              <div className="flex gap-4">
                <Select value={method} onValueChange={setMethod}>
                  <SelectTrigger className="w-32">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {Object.keys(methodConfig).map((m) => (
                      <SelectItem key={m} value={m}>
                        <Badge className={methodConfig[m as keyof typeof methodConfig].color}>
                          {m}
                        </Badge>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  placeholder="/api/v1/endpoint"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="flex-1"
                />
                <Button 
                  onClick={sendRequest}
                  disabled={isLoading}
                  className="gap-2"
                >
                  {isLoading ? (
                    <>
                      <div className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                      Sending...
                    </>
                  ) : (
                    <>
                      <Play className="h-4 w-4" />
                      Send Request
                    </>
                  )}
                </Button>
              </div>

              {/* Tabs for Headers, Query, Body */}
              <Tabs defaultValue="headers" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="headers">Headers</TabsTrigger>
                  <TabsTrigger value="query">Query Params</TabsTrigger>
                  <TabsTrigger value="body">Body</TabsTrigger>
                </TabsList>

                <TabsContent value="headers" className="space-y-3">
                  {headers.map((header, index) => (
                    <div key={index} className="flex gap-2">
                      <Input
                        placeholder="Header name"
                        value={header.key}
                        onChange={(e) => updateHeader(index, "key", e.target.value)}
                        className="flex-1"
                      />
                      <Input
                        placeholder="Header value"
                        value={header.value}
                        onChange={(e) => updateHeader(index, "value", e.target.value)}
                        className="flex-1"
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => removeHeader(index)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                  <Button variant="outline" onClick={addHeader} className="gap-2">
                    <Plus className="h-4 w-4" />
                    Add Header
                  </Button>
                </TabsContent>

                <TabsContent value="query" className="space-y-3">
                  {queryParams.map((param, index) => (
                    <div key={index} className="flex gap-2">
                      <Input
                        placeholder="Parameter name"
                        value={param.key}
                        onChange={(e) => updateQueryParam(index, "key", e.target.value)}
                        className="flex-1"
                      />
                      <Input
                        placeholder="Parameter value"
                        value={param.value}
                        onChange={(e) => updateQueryParam(index, "value", e.target.value)}
                        className="flex-1"
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => removeQueryParam(index)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                  <Button variant="outline" onClick={addQueryParam} className="gap-2">
                    <Plus className="h-4 w-4" />
                    Add Parameter
                  </Button>
                </TabsContent>

                <TabsContent value="body">
                  <Textarea
                    placeholder="Request body (JSON)"
                    value={body}
                    onChange={(e) => setBody(e.target.value)}
                    className="min-h-32 font-mono text-sm"
                  />
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Response */}
          {response && (
            <motion.div
              variants={cardVariants}
              initial="hidden"
              animate="visible"
            >
              <Card>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="flex items-center gap-2">
                      {response.status < 400 ? (
                        <CheckCircle className="h-5 w-5 text-green-600" />
                      ) : response.status < 500 ? (
                        <AlertTriangle className="h-5 w-5 text-yellow-600" />
                      ) : (
                        <XCircle className="h-5 w-5 text-red-600" />
                      )}
                      Response
                    </CardTitle>
                    <div className="flex items-center gap-2">
                      <Badge 
                        variant={response.status < 400 ? "default" : "destructive"}
                      >
                        {response.status} {response.statusText}
                      </Badge>
                      <div className="flex items-center gap-1 text-sm text-gray-500">
                        <Zap className="h-3 w-3" />
                        {Math.round(response.time)}ms
                      </div>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Response Headers */}
                  <div>
                    <h4 className="text-sm font-semibold text-gray-900 mb-2">Response Headers</h4>
                    <div className="bg-gray-50 p-3 rounded-lg">
                      {Object.entries(response.headers).map(([key, value]) => (
                        <div key={key} className="flex justify-between text-sm">
                          <span className="font-medium text-gray-700">{key}:</span>
                          <span className="text-gray-600">{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Response Body */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-semibold text-gray-900">Response Body</h4>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyToClipboard(JSON.stringify(response.body, null, 2))}
                          className="gap-1"
                        >
                          <Copy className="h-3 w-3" />
                          Copy
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyToClipboard(generateCurl())}
                          className="gap-1"
                        >
                          <Terminal className="h-3 w-3" />
                          cURL
                        </Button>
                      </div>
                    </div>
                    <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm">
                      {JSON.stringify(response.body, null, 2)}
                    </pre>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </motion.div>
      </div>
    </div>
  );
}