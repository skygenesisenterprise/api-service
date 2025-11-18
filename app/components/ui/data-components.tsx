"use client"

import { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "../ui/card"
import { Badge } from "../ui/badge"
import { Button } from "../ui/button"
import { 
  MoreHorizontal, 
  Download, 
  RefreshCw, 
  Eye,
  Calendar,
  Filter,
  Search,
  Plus
} from "lucide-react"
import { motion } from "framer-motion"
import { 
  LineChart, 
  Line, 
  AreaChart, 
  Area, 
  BarChart, 
  Bar, 
  PieChart, 
  Pie, 
  Cell, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Legend 
} from "recharts"

interface ChartContainerProps {
  title: string
  description?: string
  children: React.ReactNode
  actions?: React.ReactNode
  className?: string
}

export function ChartContainer({ title, description, children, actions, className = "" }: ChartContainerProps) {
  return (
    <Card className={`${className} transition-all duration-300 hover:shadow-lg`}>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <div className="space-y-1">
          <CardTitle className="text-lg font-semibold text-gray-900">
            {title}
          </CardTitle>
          {description && (
            <p className="text-sm text-gray-600 leading-relaxed">
              {description}
            </p>
          )}
        </div>
        {actions && (
          <div className="flex items-center gap-2">
            {actions}
          </div>
        )}
      </CardHeader>
      <CardContent className="p-6">
        {children}
      </CardContent>
    </Card>
  )
}

interface DataTableProps {
  title: string
  data: any[]
  columns: {
    key: string
    title: string
    render?: (value: any, row: any) => React.ReactNode
  }[]
  actions?: (row: any) => React.ReactNode
  searchable?: boolean
  filterable?: boolean
  loading?: boolean
}

export function DataTable({ title, data, columns, actions, searchable = false, filterable = false, loading = false }: DataTableProps) {
  const [searchTerm, setSearchTerm] = useState("")
  const [filterValue, setFilterValue] = useState("")

  const filteredData = data.filter(row => {
    const matchesSearch = !searchable || searchTerm === "" || 
      columns.some(col => {
        const value = row[col.key]
        return value && value.toString().toLowerCase().includes(searchTerm.toLowerCase())
      })
    
    const matchesFilter = !filterable || filterValue === "" || 
      Object.values(row).some(value => 
        value && value.toString().toLowerCase().includes(filterValue.toLowerCase())
      )
    
    return matchesSearch && matchesFilter
  })

  return (
    <Card className="transition-all duration-300 hover:shadow-lg">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-4">
        <div className="space-y-1">
          <CardTitle className="text-lg font-semibold text-gray-900">
            {title}
          </CardTitle>
          <p className="text-sm text-gray-600">
            {data.length} {data.length === 1 ? 'résultat' : 'résultats'} trouvés
          </p>
        </div>
        
        <div className="flex items-center gap-2">
          {searchable && (
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Rechercher..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              />
            </div>
          )}
          
          {filterable && (
            <select
              value={filterValue}
              onChange={(e) => setFilterValue(e.target.value)}
              className="px-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            >
              <option value="">Tous</option>
              <option value="active">Actifs</option>
              <option value="inactive">Inactifs</option>
            </select>
          )}
          
          <Button variant="outline" size="sm">
            <RefreshCw className="w-4 h-4" />
          </Button>
          
          <Button variant="outline" size="sm">
            <Download className="w-4 h-4" />
          </Button>
        </div>
      </CardHeader>
      
      <CardContent className="p-0">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  {columns.map((column) => (
                    <th
                      key={column.key}
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                    >
                      {column.title}
                    </th>
                  ))}
                  {actions && (
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Actions
                    </th>
                  )}
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredData.map((row, index) => (
                  <motion.tr
                    key={row.id || index}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: index * 0.05 }}
                    className="hover:bg-gray-50 transition-colors"
                  >
                    {columns.map((column) => (
                      <td key={column.key} className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                        {column.render ? column.render(row[column.key], row) : row[column.key]}
                      </td>
                    ))}
                    {actions && (
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end gap-2">
                          {actions(row)}
                        </div>
                      </td>
                    )}
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

interface StatusBadgeProps {
  status: 'active' | 'inactive' | 'pending' | 'success' | 'warning' | 'error'
  children?: React.ReactNode
  className?: string
}

export function StatusBadge({ status, children, className = "" }: StatusBadgeProps) {
  const getStatusStyles = () => {
    switch (status) {
      case 'active':
        return 'bg-green-100 text-green-800 border-green-200'
      case 'inactive':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'pending':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'success':
        return 'bg-green-100 text-green-800 border-green-200'
      case 'warning':
        return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'error':
        return 'bg-red-100 text-red-800 border-red-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getStatusText = () => {
    switch (status) {
      case 'active': return 'Actif'
      case 'inactive': return 'Inactif'
      case 'pending': return 'En attente'
      case 'success': return 'Succès'
      case 'warning': return 'Attention'
      case 'error': return 'Erreur'
      default: return 'Inconnu'
    }
  }

  return (
    <Badge 
      variant="secondary" 
      className={`${getStatusStyles()} ${className} px-3 py-1 text-xs font-medium`}
    >
      <span className="flex items-center gap-1">
        {children}
        <span className="ml-1 opacity-70">{getStatusText()}</span>
      </span>
    </Badge>
  )
}