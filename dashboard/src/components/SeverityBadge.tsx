import { clsx } from 'clsx';

interface Props {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  size?: 'sm' | 'md';
}

const styles = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-200',
  HIGH:     'bg-orange-100 text-orange-800 border-orange-200',
  MEDIUM:   'bg-yellow-100 text-yellow-800 border-yellow-200',
  LOW:      'bg-green-100 text-green-800 border-green-200',
  INFO:     'bg-blue-100 text-blue-800 border-blue-200',
};

const icons = {
  CRITICAL: '🔴',
  HIGH:     '🟠',
  MEDIUM:   '🟡',
  LOW:      '🟢',
  INFO:     'ℹ️',
};

export function SeverityBadge({ severity, size = 'md' }: Props) {
  return (
    <span className={clsx(
      'inline-flex items-center gap-1 rounded-full border font-semibold',
      size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm',
      styles[severity]
    )}>
      <span>{icons[severity]}</span>
      {severity}
    </span>
  );
}
