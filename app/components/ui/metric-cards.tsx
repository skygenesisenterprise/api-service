"use client"

import { Card, CardContent } from "../ui/card"
import { Badge } from "../ui/badge"
import { 
  TrendingUp, 
  TrendingDown, 
  Minus,
  Activity,
  Users,
  Server,
  Database,
  Globe,
  Zap,
  Shield,
  Clock,
  AlertTriangle
} from "lucide-react"
import { motion } from "framer-motion"

interface MetricCardProps {
  title: string
  value: string | number
  change?: number
  changeType?: 'increase' | 'decrease' | 'neutral'
  icon: React.ReactNode
  description?: string
  status?: 'success' | 'warning' | 'error' | 'info'
  trend?: 'up' | 'down' | 'stable'
  loading?: boolean
}

export function MetricCard({ 
  title, 
  value, 
  change, 
  changeType = 'neutral', 
  icon, 
  description, 
  status = 'info',
  trend = 'stable',
  loading = false
}: MetricCardProps) {
  const getStatusColor = () => {
    switch (status) {
      case 'success': return 'text-green-600 bg-green-50 border-green-200'
      case 'warning': return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      case 'error': return 'text-red-600 bg-red-50 border-red-200'
      default: return 'text-blue-600 bg-blue-50 border-blue-200'
    }
  }

  const getTrendIcon = () => {
    switch (trend) {
      case 'up': return <TrendingUp className="w-4 h-4 text-green-500" />
      case 'down': return <TrendingDown className="w-4 h-4 text-red-500" />
      default: return <Minus className="w-4 h-4 text-gray-400" />
    }
  }

  const getChangeColor = () => {
    if (changeType === 'increase') return 'text-green-600'
    if (changeType === 'decrease') return 'text-red-600'
    return 'text-gray-600'
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.1 }}
      whileHover={{ y: -4, transition: { duration: 0.2 } }}
    >
      <Card className={`relative overflow-hidden border-2 ${getStatusColor()} transition-all duration-300 hover:shadow-lg`}>
        <CardContent className="p-6">
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <h3 className="text-sm font-semibold text-gray-700 uppercase tracking-wide">
                  {title}
                </h3>
                {status !== 'info' && (
                  <Badge 
                    variant="secondary" 
                    className={`text-xs ${
                      status === 'success' ? 'bg-green-100 text-green-700' :
                      status === 'warning' ? 'bg-yellow-100 text-yellow-700' :
                      status === 'error' ? 'bg-red-100 text-red-700' : ''
                    }`}
                  >
                    {status === 'success' ? 'Opérationnel' :
                     status === 'warning' ? 'Attention' :
                     status === 'error' ? 'Critique' : 'Info'}
                  </Badge>
                )}
              </div>
              
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-gray-900">
                  {loading ? (
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 bg-gray-200 rounded animate-pulse" />
                      <div className="w-2 h-2 bg-gray-200 rounded animate-pulse" />
                    </div>
                  ) : (
                    typeof value === 'number' ? value.toLocaleString() : value
                  )}
                </span>
                
                {change !== undefined && (
                  <div className={`flex items-center gap-1 text-sm font-medium ${getChangeColor()}`}>
                    {getTrendIcon()}
                    <span>{Math.abs(change)}%</span>
                  </div>
                )}
              </div>
              
              {description && (
                <p className="text-sm text-gray-600 mt-2 leading-relaxed">
                  {description}
                </p>
              )}
            </div>
            
            <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br from-gray-50 to-gray-100 border border-gray-200">
              {icon}
            </div>
          </div>
          
          {/* Progress indicator for loading state */}
          {loading && (
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-200">
              <motion.div 
                className="h-full bg-blue-500"
                initial={{ width: "0%" }}
                animate={{ width: "100%" }}
                transition={{ duration: 1.5, repeat: Infinity, repeatType: "reverse" }}
              />
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  )
}

interface MetricGridProps {
  children: React.ReactNode
  columns?: 1 | 2 | 3 | 4
}

export function MetricGrid({ children, columns = 4 }: MetricGridProps) {
  const gridCols = {
    1: 'grid-cols-1',
    2: 'grid-cols-1 md:grid-cols-2',
    3: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-3',
    4: 'grid-cols-1 md:grid-cols-2 lg:grid-cols-4'
  }

  return (
    <div className={`grid gap-6 ${gridCols[columns]}`}>
      {children}
    </div>
  )
}