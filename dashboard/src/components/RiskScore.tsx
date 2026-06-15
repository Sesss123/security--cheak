import { clsx } from 'clsx';

interface Props {
  score: number;
  size?: 'sm' | 'lg';
}

function getRiskColor(score: number) {
  if (score >= 8) return { ring: 'ring-red-500',    text: 'text-red-600',    label: 'CRITICAL' };
  if (score >= 6) return { ring: 'ring-orange-500', text: 'text-orange-600', label: 'HIGH' };
  if (score >= 4) return { ring: 'ring-yellow-500', text: 'text-yellow-600', label: 'MEDIUM' };
  if (score >= 2) return { ring: 'ring-green-500',  text: 'text-green-600',  label: 'LOW' };
  return              { ring: 'ring-blue-500',   text: 'text-blue-600',   label: 'MINIMAL' };
}

export function RiskScore({ score, size = 'lg' }: Props) {
  const { ring, text, label } = getRiskColor(score);
  const pct = (score / 10) * 100;

  if (size === 'sm') {
    return (
      <span className={clsx('font-bold tabular-nums', text)}>
        {score.toFixed(1)}
      </span>
    );
  }

  return (
    <div className="flex flex-col items-center gap-2">
      <div className={clsx('relative flex h-24 w-24 items-center justify-center rounded-full ring-4', ring, 'bg-white')}>
        <div className="text-center">
          <div className={clsx('text-2xl font-bold', text)}>{score.toFixed(1)}</div>
          <div className="text-xs text-gray-500">/ 10</div>
        </div>
      </div>
      <span className={clsx('text-sm font-semibold', text)}>{label}</span>
    </div>
  );
}
